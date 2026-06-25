// Package cpuprofiler é o perfilador de CPU por amostragem via eBPF (perf_event +
// bpf_get_stackid), ISOLADO do tracer L7 (internal/ebpf). Carrega sua própria
// *ebpf.Collection, anexa um perf_event de PERF_COUNT_SW_CPU_CLOCK por CPU a ~N Hz,
// e a cada janela drena o histograma de pilhas, simboliza e dobra em "folded
// stacks" por serviço — o mesmo formato que o profiler JFR (Opção A) já manda.
//
// Best-effort: se o verifier rejeitar a coleção (kernel sem suporte), o caller só
// desliga o profiler; o eBPF L7 nunca é tocado. Roda atrás de ISPWATCH_PROFILING_ENABLED.
//
// source="ebpf"; o JFR continua cobrindo Java. Simbolização de kernel via
// /proc/kallsyms aqui; símbolos de user (ELF por linguagem) ficam pra S3.
package cpuprofiler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/ispwatch/collector/internal/ebpf/common"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	defaultHz       = 49               // Hz ímpar: evita lock-step com timers do app
	defaultInterval = 15 * time.Second // janela de flush (igual ordem de grandeza do JFR)
	maxStackDepth   = 127              // teto do kernel (PERF_MAX_STACK_DEPTH); casa com o .c
)

// ServiceResolver mapeia um PID a (service, namespace, pod). Injetado pelo caller
// (PodResolverImpl em k8s, DockerContainerResolver em bare-metal) pra não acoplar
// o profiler ao ambiente. service vazio → o caller dobra sob o nome do processo.
type ServiceResolver interface {
	ResolveProfile(pid uint32) (service, namespace, pod string)
}

// Window é uma janela de profile agregada por serviço, no formato que o backend
// (ProfileIngestResource / noc_profile) espera.
type Window struct {
	Service       string
	Namespace     string
	Pod           string
	ProfileType   string // "cpu"
	Source        string // "ebpf"
	PeriodMs      int
	WindowStartMs int64
	WindowSeconds int
	Folded        string // collapsed stacks: "raiz;...;folha N\n" por linha
}

// EmitFunc recebe as janelas a cada flush (print no S1, sender → ingest no S2).
type EmitFunc func(ctx context.Context, windows []Window)

// Config injeta as dependências do profiler.
type Config struct {
	Hz       int             // amostragem; 0 → defaultHz
	Interval time.Duration   // flush; 0 → defaultInterval
	Resolver ServiceResolver // PID → serviço; pode ser nil (dobra por comm)
	Emit     EmitFunc        // saída das janelas; obrigatório
}

// Profiler encapsula a coleção eBPF do profiler e o laço de drain.
type Profiler struct {
	hz       int
	interval time.Duration
	resolver ServiceResolver
	emit     EmitFunc

	coll    *ebpf.Collection
	counts  *ebpf.Map
	stacks  *ebpf.Map
	perfFDs []int
	ksyms   *kallsyms
}

// sampleKey espelha `struct sample_key` do cpuprofile.c (layout C, 40 bytes:
// u32 pid + 4 pad + s64 kstack + s64 ustack + char[16] comm).
type sampleKey struct {
	Pid         uint32
	Pad         uint32
	KernStackID int64
	UserStackID int64
	Comm        [16]byte
}

// New cria o profiler (não carrega nada ainda — isso é no Run).
func New(cfg Config) *Profiler {
	hz := cfg.Hz
	if hz <= 0 {
		hz = defaultHz
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Profiler{hz: hz, interval: interval, resolver: cfg.Resolver, emit: cfg.Emit}
}

// Run carrega a coleção, anexa os perf_events por CPU e drena num laço até
// ctx.Done(). Retorna erro se o load/attach falhar (caller loga e desiste — o L7
// segue intacto). Bloqueante: rode em goroutine.
func (p *Profiler) Run(ctx context.Context) error {
	if err := p.load(); err != nil {
		return err
	}
	defer p.Close()

	if err := p.attach(); err != nil {
		return fmt.Errorf("perf_event attach: %w", err)
	}
	p.ksyms = loadKallsyms() // best-effort; nil se kptr_restrict

	klog.Infof("cpuprofiler: ligado — %d Hz, flush a cada %s, %d CPUs anexadas",
		p.hz, p.interval, len(p.perfFDs))

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	windowStart := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.flush(ctx, windowStart)
			windowStart = time.Now()
		}
	}
}

// load seleciona a variante por arch+kernel e cria a coleção (SEM LogLevel —
// mesmo motivo do tracer.go: deadlock do verifier em kernel grande no 6.8).
func (p *Profiler) load() error {
	prog, err := selectProg()
	if err != nil {
		return err
	}
	reader, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(prog)))
	if err != nil {
		return fmt.Errorf("encoding inválido: %w", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("ungzip: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var vErr *ebpf.VerifierError
		if errors.As(err, &vErr) {
			klog.Errorf("cpuprofiler: verifier rejeitou (kernel sem suporte): %+v", vErr)
		}
		return fmt.Errorf("load collection: %w", err)
	}
	p.coll = coll
	p.counts = coll.Maps["counts"]
	p.stacks = coll.Maps["stacks"]
	if p.counts == nil || p.stacks == nil {
		coll.Close()
		return fmt.Errorf("maps counts/stacks ausentes na coleção")
	}
	return nil
}

// selectProg replica a seleção do tracer.go (maior version <= kernel atual).
func selectProg() ([]byte, error) {
	entries, ok := cpuProfilerProgs[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("arquitetura não suportada: %s", runtime.GOARCH)
	}
	kv := detectKernel()
	for _, e := range entries {
		ev, _ := common.VersionFromString(e.version)
		if kv.GreaterOrEqual(ev) {
			return e.prog, nil
		}
	}
	return nil, fmt.Errorf("kernel não suportado: %s", kv)
}

// detectKernel usa o global do pkg common se já setado (modo L7), senão lê o
// uname direto — o profiler pode rodar sem o L7 ligado.
func detectKernel() common.Version {
	if kv := common.GetKernelVersion(); kv.Major != 0 {
		return kv
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		kv, _ := common.VersionFromString(nulString(uts.Release[:]))
		return kv
	}
	return common.Version{}
}

// attach abre um perf_event de CPU-clock por CPU e amarra o programa do_perf_event.
func (p *Profiler) attach() error {
	prog := p.coll.Programs["do_perf_event"]
	if prog == nil {
		return fmt.Errorf("programa do_perf_event ausente na coleção")
	}
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK, // tempo de CPU, não wall-clock
		Bits:   unix.PerfBitFreq,             // Sample é frequência (Hz)
		Sample: uint64(p.hz),
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		fd, err := unix.PerfEventOpen(&attr, -1 /*todos os PIDs*/, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			klog.Warningf("cpuprofiler: perf_event_open cpu=%d falhou (offline/paranoid?): %v", cpu, err)
			continue
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			unix.Close(fd)
			return fmt.Errorf("IOC_SET_BPF cpu=%d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			unix.Close(fd)
			return fmt.Errorf("IOC_ENABLE cpu=%d: %w", cpu, err)
		}
		p.perfFDs = append(p.perfFDs, fd)
	}
	if len(p.perfFDs) == 0 {
		return fmt.Errorf("nenhum perf_event aberto (perf_event_paranoid? sem privilégio?)")
	}
	return nil
}

// Close desliga os perf_events e fecha a coleção. Idempotente.
func (p *Profiler) Close() {
	for _, fd := range p.perfFDs {
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		_ = unix.Close(fd)
	}
	p.perfFDs = nil
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
}

// flush drena o histograma da janela, dobra por serviço e emite. Depois zera a
// janela (apaga as chaves drenadas e os stackids lidos).
func (p *Profiler) flush(ctx context.Context, windowStart time.Time) {
	type svc struct{ service, namespace, pod string }
	agg := map[svc]map[string]int64{}
	var drained []sampleKey
	stackIDs := map[uint32]struct{}{}

	var key sampleKey
	var count uint64
	iter := p.counts.Iterate()
	for iter.Next(&key, &count) {
		drained = append(drained, key)
		if key.KernStackID >= 0 {
			stackIDs[uint32(key.KernStackID)] = struct{}{}
		}
		if key.UserStackID >= 0 {
			stackIDs[uint32(key.UserStackID)] = struct{}{}
		}
		if count == 0 {
			continue
		}
		comm := nulString(key.Comm[:])
		service, namespace, pod := "", "", ""
		if p.resolver != nil {
			service, namespace, pod = p.resolver.ResolveProfile(key.Pid)
		}
		if service == "" {
			service = comm // fallback: agrupa pelo nome do processo
		}
		line := p.foldLine(key, comm)
		k := svc{service, namespace, pod}
		m := agg[k]
		if m == nil {
			m = map[string]int64{}
			agg[k] = m
		}
		m[line] += int64(count)
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("cpuprofiler: iterate counts: %v", err)
	}

	// zera a janela: apaga contagens drenadas + stackids lidos (senão o
	// STACK_TRACE map enche e bpf_get_stackid passa a falhar).
	for i := range drained {
		_ = p.counts.Delete(&drained[i])
	}
	for id := range stackIDs {
		id := id
		_ = p.stacks.Delete(&id)
	}

	if len(agg) == 0 {
		return
	}
	periodMs := 1000 / p.hz
	if periodMs <= 0 {
		periodMs = 1
	}
	windowSeconds := int(time.Since(windowStart).Seconds() + 0.5)
	startMs := windowStart.UnixMilli()
	windows := make([]Window, 0, len(agg))
	for k, lines := range agg {
		var sb strings.Builder
		for line, c := range lines {
			sb.WriteString(line)
			sb.WriteByte(' ')
			sb.WriteString(strconv.FormatInt(c, 10))
			sb.WriteByte('\n')
		}
		windows = append(windows, Window{
			Service: k.service, Namespace: k.namespace, Pod: k.pod,
			ProfileType: "cpu", Source: "ebpf", PeriodMs: periodMs,
			WindowStartMs: startMs, WindowSeconds: windowSeconds, Folded: sb.String(),
		})
	}
	if p.emit != nil {
		p.emit(ctx, windows)
	}
}

// foldLine monta a pilha colapsada (raiz→folha): comm como raiz, depois os frames
// de user (raiz→folha), depois os de kernel (prefixo "[k] "). bpf_get_stackid
// devolve folha→raiz, então invertemos. Símbolos de user = hex no S1 (S3 resolve).
func (p *Profiler) foldLine(key sampleKey, comm string) string {
	frames := []string{comm}
	if key.UserStackID >= 0 {
		user := p.readStack(uint32(key.UserStackID))
		for i := len(user) - 1; i >= 0; i-- {
			frames = append(frames, "0x"+strconv.FormatUint(user[i], 16))
		}
	}
	if key.KernStackID >= 0 {
		kern := p.readStack(uint32(key.KernStackID))
		for i := len(kern) - 1; i >= 0; i-- {
			name := "0x" + strconv.FormatUint(kern[i], 16)
			if p.ksyms != nil {
				if s := p.ksyms.resolve(kern[i]); s != "" {
					name = s
				}
			}
			frames = append(frames, "[k] "+name)
		}
	}
	return strings.Join(frames, ";")
}

// readStack lê os IPs de um stackid (para no primeiro 0 = fim da pilha).
func (p *Profiler) readStack(id uint32) []uint64 {
	var buf [maxStackDepth]uint64
	if err := p.stacks.Lookup(&id, &buf); err != nil {
		return nil
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return buf[:n]
}

// nulString converte um buffer C terminado em NUL numa string Go.
func nulString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
