// journald.go — reader de logs do systemd journal via subprocess
// `journalctl -f -o json --no-pager`.
//
// Por que subprocess e não cgo sd-journal: cross-compile pra arm64 fica
// trivial sem dep dinâmica de libsystemd. Em troca, dependemos do binário
// `journalctl` existir no PATH (vem em todo host systemd-based —
// ubuntu/debian/rhel/sles 7+).
//
// Cada linha de saída do journalctl é 1 record JSON. Campos relevantes:
//   __REALTIME_TIMESTAMP  — microsegundos epoch (string)
//   _SYSTEMD_UNIT          — unit que emitiu (ex: "nginx.service")
//   MESSAGE                — texto do log (pode ser array de bytes em rare cases)
//   PRIORITY               — severity syslog 0-7 (string)
//   _HOSTNAME              — hostname do host
//   _PID                   — pid do processo
//   SYSLOG_IDENTIFIER      — fallback se _SYSTEMD_UNIT vazio
//
// Mapping PRIORITY → OTel severity_number:
//   0 emerg, 1 alert, 2 crit, 3 err  → 17/18/19/17 (ERROR)
//   4 warning                        → 13 (WARN)
//   5 notice, 6 info                 → 9/9  (INFO)
//   7 debug                          → 5  (DEBUG)
//
// Rate limit: max ratelimitLines/sec por unit. Drops bumpam counter
// reportado via Stats() pro main publisher emitir como self-metric.

package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"syscall"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ratelimitLines — max linhas/seg por unit antes de drop. App quebrada
	// pode logar centenas de milhares/s, o que satura o pipe. 1000 é teto
	// generoso pra qualquer cenário legítimo de produção.
	ratelimitLines = 1000

	// ratelimitWindow — janela do contador. Reseta a cada N ms.
	ratelimitWindow = 1 * time.Second

	// JournaldUnitInitScope — unit poluída por logs do systemd boot,
	// containers transientes (systemd-run), etc. Dropada por default.
	JournaldUnitInitScope = "init.scope"

	// readDeadline — se o subprocess não emite nada por muito tempo é OK
	// (sistema quieto). Usamos um deadline curto só pro select interno do
	// flush funcionar; o scanner não tem timeout próprio.
	flushInterval = 200 * time.Millisecond
)

// JournaldRecord é o subset que consumimos do JSON emitido pelo journalctl.
// Mantemos campos opcionais como string mesmo quando o journal poderia
// devolver array de bytes; nessas exceções (`MESSAGE` raro como [byte]),
// fazemos best-effort de decode no parser.
type JournaldRecord struct {
	TimestampUnixNano int64             `json:"-"` // derivado de __REALTIME_TIMESTAMP
	Unit              string            `json:"-"` // _SYSTEMD_UNIT ou SYSLOG_IDENTIFIER
	Priority          int               `json:"-"` // 0-7 syslog
	Body              string            `json:"-"` // MESSAGE
	Hostname          string            `json:"-"` // _HOSTNAME
	PID               string            `json:"-"` // _PID
	Extras            map[string]string `json:"-"` // demais campos como string
}

// parseJournaldLine decodifica 1 linha JSON do journalctl no record canônico.
// Tolerante: linhas inválidas devolvem err pra caller dropar.
func parseJournaldLine(line []byte) (JournaldRecord, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return JournaldRecord{}, fmt.Errorf("decode json: %w", err)
	}

	rec := JournaldRecord{Extras: map[string]string{}}

	// __REALTIME_TIMESTAMP — microsegundos epoch como string.
	if v, ok := raw["__REALTIME_TIMESTAMP"]; ok {
		if s, ok := v.(string); ok {
			if usec, err := strconv.ParseInt(s, 10, 64); err == nil {
				rec.TimestampUnixNano = usec * 1000 // µs → ns
			}
		}
	}
	if rec.TimestampUnixNano == 0 {
		rec.TimestampUnixNano = time.Now().UnixNano()
	}

	// _SYSTEMD_UNIT (preferido). Fallback pra SYSLOG_IDENTIFIER pra processos
	// que não rodam dentro de unit explícita (ex: sshd em alguns hosts).
	if s := stringField(raw, "_SYSTEMD_UNIT"); s != "" {
		rec.Unit = s
	} else if s := stringField(raw, "SYSLOG_IDENTIFIER"); s != "" {
		rec.Unit = s
	} else {
		rec.Unit = "unknown"
	}

	// PRIORITY — vem como string "0".."7" no journal JSON.
	rec.Priority = 6 // default INFO se ausente/inválido
	if s := stringField(raw, "PRIORITY"); s != "" {
		if p, err := strconv.Atoi(s); err == nil && p >= 0 && p <= 7 {
			rec.Priority = p
		}
	}

	// MESSAGE — geralmente string. Em rare cases o journal embute bytes
	// brutos como array de inteiros. Nesse caso decodificamos best-effort.
	switch msg := raw["MESSAGE"].(type) {
	case string:
		rec.Body = msg
	case []any:
		// Array of byte values — converter pra string.
		buf := make([]byte, 0, len(msg))
		for _, b := range msg {
			if f, ok := b.(float64); ok && f >= 0 && f <= 255 {
				buf = append(buf, byte(f))
			}
		}
		rec.Body = string(buf)
	}

	rec.Hostname = stringField(raw, "_HOSTNAME")
	rec.PID = stringField(raw, "_PID")

	// Coleta atributos comuns que ajudam debug no UI. Não floodamos —
	// pegamos só os mais interessantes pra evitar JSONB inflado no backend.
	for _, k := range []string{
		"SYSLOG_IDENTIFIER", "_COMM", "_EXE", "_CMDLINE",
		"_UID", "_GID", "CODE_FILE", "CODE_FUNC", "CODE_LINE",
	} {
		if s := stringField(raw, k); s != "" {
			rec.Extras[strings.ToLower(k)] = s
		}
	}

	return rec, nil
}

func stringField(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PriorityToSeverityNumber mapeia syslog priority (0-7) → OTel severity_number
// per OpenTelemetry spec (https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber).
func PriorityToSeverityNumber(p int) int {
	switch {
	case p <= 0:
		return 21 // FATAL
	case p == 1:
		return 21 // FATAL (alert)
	case p == 2:
		return 21 // FATAL (crit)
	case p == 3:
		return 17 // ERROR
	case p == 4:
		return 13 // WARN
	case p == 5:
		return 9 // INFO (notice)
	case p == 6:
		return 9 // INFO
	case p == 7:
		return 5 // DEBUG
	}
	return 9
}

func PriorityToSeverityText(p int) string {
	switch {
	case p <= 2:
		return "FATAL"
	case p == 3:
		return "ERROR"
	case p == 4:
		return "WARN"
	case p == 5, p == 6:
		return "INFO"
	case p == 7:
		return "DEBUG"
	}
	return "INFO"
}

// JournaldStats — snapshot consumido pelo publisher de self-metrics.
// Counters cumulativos; dashboard aplica rate().
type JournaldStats struct {
	LinesTotal   int64
	BytesTotal   int64
	DroppedTotal int64
	// PerUnitDropped: counter de drop por unit (sample da última janela —
	// não acumula pra evitar mapa unbounded).
	PerUnitDropped map[string]int64
}

// JournaldReader gerencia o ciclo de vida do subprocess journalctl e
// emite JournaldRecord pelo channel Out. Pra ser usado, o caller faz:
//
//	r := NewJournaldReader(log)
//	go r.Run(ctx)
//	for rec := range r.Out() { ... }
//
// Close-by-context: cancelar o context envia SIGTERM ao subprocess e
// fecha o channel Out depois do drain. Out é buffered (256) pra absorver
// rajadas curtas sem bloquear o reader; overflow vira drop com counter.
type JournaldReader struct {
	log *slog.Logger
	out chan JournaldRecord

	// Cmd override pra testes (mock binário). Se vazio, "journalctl".
	cmdName string
	cmdArgs []string

	mu             sync.Mutex
	rateBuckets    map[string]*rateBucket // por unit
	linesTotal     atomic.Int64
	bytesTotal     atomic.Int64
	droppedTotal   atomic.Int64
	droppedPerUnit map[string]*atomic.Int64
}

type rateBucket struct {
	count     int64
	windowEnd time.Time
}

// NewJournaldReader monta o reader com defaults. Out buffer = 256
// (~256ms de log a 1000 lines/s antes de bloquear consumer).
func NewJournaldReader(log *slog.Logger) *JournaldReader {
	return &JournaldReader{
		log:            log.With("component", "journald-reader"),
		out:            make(chan JournaldRecord, 256),
		rateBuckets:    map[string]*rateBucket{},
		droppedPerUnit: map[string]*atomic.Int64{},
	}
}

// Out é o channel onde os records chegam. Caller é responsável por consumir;
// se travar mais que cap(out) records, novos chegam dropados (best-effort).
func (r *JournaldReader) Out() <-chan JournaldRecord { return r.out }

// Stats retorna snapshot dos counters acumulados pelo reader.
func (r *JournaldReader) Stats() JournaldStats {
	r.mu.Lock()
	per := make(map[string]int64, len(r.droppedPerUnit))
	for u, c := range r.droppedPerUnit {
		per[u] = c.Load()
	}
	r.mu.Unlock()
	return JournaldStats{
		LinesTotal:     r.linesTotal.Load(),
		BytesTotal:     r.bytesTotal.Load(),
		DroppedTotal:   r.droppedTotal.Load(),
		PerUnitDropped: per,
	}
}

// Run mantém o subprocess vivo. Se ele crashar (binário removido, kernel
// quebrou, etc.) loga e re-tenta com backoff exponencial até ctx ser
// cancelado. Encerra limpo (close de Out) no shutdown.
func (r *JournaldReader) Run(ctx context.Context) {
	defer close(r.out)
	backoff := time.Second
	for {
		err := r.runOnce(ctx)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		if err != nil {
			r.log.Warn("journalctl subprocess exited, restarting", "err", err, "backoff", backoff)
		} else {
			r.log.Warn("journalctl subprocess exited cleanly, restarting", "backoff", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// runOnce executa o subprocess uma vez e drena seu stdout até EOF/erro.
// Argumentos:
//   -f          follow (long-running stream)
//   -o json     formato JSON line-oriented
//   --no-pager  não bloqueia esperando "more"
//   -n 0        não imprime backlog histórico (só logs novos a partir de agora)
func (r *JournaldReader) runOnce(ctx context.Context) error {
	name := r.cmdName
	if name == "" {
		name = "journalctl"
	}
	args := r.cmdArgs
	if len(args) == 0 {
		args = []string{"-f", "-o", "json", "--no-pager", "-n", "0"}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	r.log.Info("journalctl subprocess started", "pid", cmd.Process.Pid)

	doneScan := make(chan error, 1)
	go func() {
		doneScan <- r.scanLoop(ctx, stdout)
	}()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM) // best-effort graceful
		_ = cmd.Process.Kill()
		<-doneScan
		_ = cmd.Wait()
		return ctx.Err()
	case scanErr := <-doneScan:
		_ = cmd.Wait()
		return scanErr
	}
}

// ScanReader é o entry-point usado pelos testes pra alimentar um io.Reader
// arbitrário (sem subprocess). Em produção é chamado por runOnce com o
// stdout do journalctl.
func (r *JournaldReader) ScanReader(ctx context.Context, src io.Reader) error {
	return r.scanLoop(ctx, src)
}

func (r *JournaldReader) scanLoop(ctx context.Context, src io.Reader) error {
	scanner := bufio.NewScanner(src)
	// Aumenta o buffer pra acomodar linhas grandes do journal (stacktraces).
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		r.bytesTotal.Add(int64(len(line)))

		rec, err := parseJournaldLine(line)
		if err != nil {
			r.log.Debug("journald parse failed (skipping line)", "err", err)
			continue
		}
		// Dropa unit poluída.
		if rec.Unit == JournaldUnitInitScope {
			continue
		}
		// Rate limit por unit.
		if !r.allow(rec.Unit) {
			r.droppedTotal.Add(1)
			r.bumpDroppedUnit(rec.Unit)
			continue
		}
		r.linesTotal.Add(1)

		select {
		case r.out <- rec:
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel cheio — consumer atrasado. Drop pra não blocar.
			r.droppedTotal.Add(1)
			r.bumpDroppedUnit(rec.Unit)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	return nil
}

func (r *JournaldReader) allow(unit string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b, ok := r.rateBuckets[unit]
	if !ok || now.After(b.windowEnd) {
		r.rateBuckets[unit] = &rateBucket{count: 1, windowEnd: now.Add(ratelimitWindow)}
		return true
	}
	if b.count >= ratelimitLines {
		return false
	}
	b.count++
	return true
}

func (r *JournaldReader) bumpDroppedUnit(unit string) {
	r.mu.Lock()
	c, ok := r.droppedPerUnit[unit]
	if !ok {
		c = &atomic.Int64{}
		r.droppedPerUnit[unit] = c
	}
	r.mu.Unlock()
	c.Add(1)
}
