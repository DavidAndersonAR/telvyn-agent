// cri_tailer.go — tailer de logs de pods no formato CRI (/var/log/pods),
// usado em k8s com containerd/CRI-O (ex: k3s). Equivalente ao docker_tailer
// mas sem depender do Docker daemon: lê os arquivos de log que o kubelet
// grava no host e deriva namespace/pod/container direto do path.
//
// Layout CRI:
//   /var/log/pods/<namespace>_<pod>_<uid>/<container>/<N>.log
// onde <N> é o restart count (0.log, 1.log, ...). Tailamos sempre o N mais
// alto (instância ativa). Cada linha do arquivo:
//   <rfc3339nano> <stdout|stderr> <F|P> <mensagem>
// F = linha completa, P = parcial (kubelet quebra linhas > ~16KB). Linhas P
// são acumuladas até o próximo F.
//
// Lifecycle (espelha o DockerLogsTailer):
//   - Discovery loop (15s): varre /var/log/pods, reconcilia readers ativos.
//   - Per-file reader (poll 1s): lê o que cresceu desde o cursor, parseia,
//     dá Push no LogsExporter (modo ingest → OTLP JSON + Bearer).
//   - Cursor (offset+inode) persistido pra sobreviver restart sem re-ler tudo.
//
// Arquivo NOVO (sem cursor) começa do EOF — só logs novos, igual o Datadog
// agent. Cursor existente resume de onde parou.
//
// Ativado via ISPWATCH_LOGS_ENABLED=1 no modo ingest.
package logs

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ispwatch/collector/internal/otlp"
)

const (
	// criPodsDir — raiz dos logs de pod no host (montada read-only no agent).
	criPodsDir = "/var/log/pods"

	// criDiscoveryInterval — frequência de revarredura de /var/log/pods.
	criDiscoveryInterval = 15 * time.Second

	// criPollInterval — frequência de leitura incremental por arquivo.
	criPollInterval = 1 * time.Second

	// criCursorFlushInterval — frequência de flush dos cursors pra disco.
	criCursorFlushInterval = 5 * time.Second

	// criMaxReadPerPoll — teto de bytes lidos por poll por arquivo (4MB),
	// pra não travar num backlog gigante de uma vez.
	criMaxReadPerPoll = 4 * 1024 * 1024

	// criMaxLineBytes — teto do acumulador de linhas parciais (P), pra evitar
	// estourar memória com uma linha lógica patológica.
	criMaxLineBytes = 256 * 1024
)

// CRILogsTailer coordena a descoberta de pods e seus readers de log.
type CRILogsTailer struct {
	exporter  *otlp.LogsExporter
	cursors   *CursorStore
	hostname  string
	excludeNS map[string]bool
	log       *slog.Logger

	mu      sync.Mutex
	readers map[string]*criReaderHandle // logfile path → handle

	linesTotal atomic.Int64
}

type criReaderHandle struct {
	done chan struct{}
}

type criFileInfo struct {
	namespace string
	pod       string
	container string
}

// NewCRILogsTailer cria o tailer. cursorPath = arquivo de cursors; hostname =
// nome do nó (vira host.name nos records); excludeNS = namespaces a ignorar
// (ex: o próprio namespace do agent, pra não criar loop de logs).
func NewCRILogsTailer(exporter *otlp.LogsExporter, cursorPath, hostname string, excludeNS []string, log *slog.Logger) *CRILogsTailer {
	ex := make(map[string]bool, len(excludeNS))
	for _, ns := range excludeNS {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			ex[ns] = true
		}
	}
	return &CRILogsTailer{
		exporter:  exporter,
		cursors:   NewCursorStore(cursorPath, log),
		hostname:  hostname,
		excludeNS: ex,
		log:       log.With("component", "cri-logs-tailer"),
		readers:   make(map[string]*criReaderHandle),
	}
}

// Run inicia o tailer. Bloqueia até ctx ser cancelado.
func (t *CRILogsTailer) Run(ctx context.Context) {
	excluded := make([]string, 0, len(t.excludeNS))
	for ns := range t.excludeNS {
		excluded = append(excluded, ns)
	}
	t.log.Info("cri logs tailer starting",
		"pods_dir", criPodsDir, "exclude_ns", strings.Join(excluded, ","))

	go t.cursorFlushLoop(ctx)

	t.discover()
	ticker := time.NewTicker(criDiscoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.shutdown()
			return
		case <-ticker.C:
			t.discover()
		}
	}
}

// CRILogsStats — contadores pra self-metrics.
type CRILogsStats struct {
	LinesTotal int64
}

func (t *CRILogsTailer) Stats() CRILogsStats {
	return CRILogsStats{LinesTotal: t.linesTotal.Load()}
}

// discover varre /var/log/pods e reconcilia readers ativos.
func (t *CRILogsTailer) discover() {
	podDirs, err := os.ReadDir(criPodsDir)
	if err != nil {
		t.log.Warn("cri: read pods dir failed", "dir", criPodsDir, "err", err)
		return
	}

	active := make(map[string]criFileInfo)
	for _, pd := range podDirs {
		if !pd.IsDir() {
			continue
		}
		namespace, pod, ok := parsePodDirName(pd.Name())
		if !ok || t.excludeNS[namespace] {
			continue
		}
		podPath := filepath.Join(criPodsDir, pd.Name())
		containerDirs, err := os.ReadDir(podPath)
		if err != nil {
			continue
		}
		for _, cd := range containerDirs {
			if !cd.IsDir() {
				continue
			}
			logFile := highestLogFile(filepath.Join(podPath, cd.Name()))
			if logFile == "" {
				continue
			}
			active[logFile] = criFileInfo{namespace: namespace, pod: pod, container: cd.Name()}
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Para readers de arquivos que não estão mais ativos (pod removido ou
	// rotacionado pra um N mais alto).
	for path, h := range t.readers {
		if _, ok := active[path]; !ok {
			close(h.done)
			delete(t.readers, path)
			t.cursors.Remove(path)
		}
	}

	// Inicia readers pra arquivos novos.
	for path, meta := range active {
		if _, ok := t.readers[path]; ok {
			continue
		}
		done := make(chan struct{})
		t.readers[path] = &criReaderHandle{done: done}
		go t.runReader(path, meta, done)
	}
}

// runReader taila um arquivo de log de container até `done` fechar.
func (t *CRILogsTailer) runReader(path string, meta criFileInfo, done chan struct{}) {
	svc := deriveK8sServiceName(meta.pod)

	var offset int64
	var inode uint64
	if c, ok := t.cursors.Get(path); ok {
		offset, inode = c.Offset, c.Inode
	} else if fi, err := os.Stat(path); err == nil {
		// Arquivo novo: começa do fim (só logs novos).
		offset, inode = fi.Size(), inodeOf(fi)
	}

	var partial strings.Builder

	readOnce := func() {
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		curInode := inodeOf(fi)
		size := fi.Size()
		if curInode != inode || size < offset {
			// Rotacionou (novo inode) ou truncou — recomeça do zero.
			offset, inode = 0, curInode
			partial.Reset()
		}
		if size <= offset {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return
		}
		limit := size - offset
		if limit > criMaxReadPerPoll {
			limit = criMaxReadPerPoll
		}
		reader := bufio.NewReader(io.LimitReader(f, limit))
		var consumed int64
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 && err == nil {
				// Linha completa (terminou em \n).
				consumed += int64(len(line))
				t.handleLine(strings.TrimRight(string(line), "\r\n"), meta, svc, &partial)
			}
			if err != nil {
				// EOF: o que sobrou (sem \n) é uma linha sendo escrita — não
				// consome, re-lê na próxima poll.
				break
			}
		}
		offset += consumed
		t.cursors.Set(path, CursorEntry{Offset: offset, Inode: inode})
	}

	ticker := time.NewTicker(criPollInterval)
	defer ticker.Stop()
	readOnce() // primeira leitura imediata
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			readOnce()
		}
	}
}

// handleLine parseia uma linha CRI e, quando completa (F), dá Push no exporter.
func (t *CRILogsTailer) handleLine(line string, meta criFileInfo, svc string, partial *strings.Builder) {
	if line == "" {
		return
	}
	// "<ts> <stream> <tag> <msg>"
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 3 {
		return
	}
	tsStr, stream, tag := parts[0], parts[1], parts[2]
	msg := ""
	if len(parts) == 4 {
		msg = parts[3]
	}

	if tag == "P" {
		if partial.Len() < criMaxLineBytes {
			partial.WriteString(msg)
		}
		return
	}
	// tag == "F" (ou desconhecido) → fecha a linha lógica.
	full := msg
	if partial.Len() > 0 {
		partial.WriteString(msg)
		full = partial.String()
		partial.Reset()
	}

	sevNum, sevText := streamToSeverity(stream)
	t.linesTotal.Add(1)
	t.exporter.Push(otlp.LogRecord{
		TimestampUnixNano: parseCRITime(tsStr),
		ServiceName:       svc,
		Hostname:          t.hostname,
		SeverityNumber:    sevNum,
		SeverityText:      sevText,
		Body:              full,
		Attributes: map[string]string{
			"k8s.namespace.name": meta.namespace,
			"k8s.pod.name":       meta.pod,
			"k8s.container.name": meta.container,
			"stream":             stream,
			"source":             "k8s",
		},
	})
}

func (t *CRILogsTailer) cursorFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(criCursorFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.cursors.Flush()
			return
		case <-ticker.C:
			t.cursors.Flush()
		}
	}
}

func (t *CRILogsTailer) shutdown() {
	t.log.Info("cri logs tailer shutting down")
	t.mu.Lock()
	for path, h := range t.readers {
		close(h.done)
		delete(t.readers, path)
	}
	t.mu.Unlock()
	t.cursors.Flush()
}

// ---- helpers ----------------------------------------------------------

// parsePodDirName quebra "<namespace>_<pod>_<uid>". namespace e pod nunca têm
// "_" (DNS-1123), então namespace=primeiro, uid=último, pod=meio.
func parsePodDirName(name string) (namespace, pod string, ok bool) {
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return "", "", false
	}
	namespace = parts[0]
	pod = strings.Join(parts[1:len(parts)-1], "_")
	if namespace == "" || pod == "" {
		return "", "", false
	}
	return namespace, pod, true
}

// highestLogFile devolve o path do <N>.log de maior N no diretório do
// container (a instância ativa). "" se não há .log numérico.
func highestLogFile(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best := -1
	bestName := ""
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(name, ".log"))
		if err != nil {
			continue // ignora rotacionados/gzip (ex: 0.log.20240101-...)
		}
		if n > best {
			best, bestName = n, name
		}
	}
	if bestName == "" {
		return ""
	}
	return filepath.Join(dir, bestName)
}

// parseCRITime parseia o timestamp RFC3339Nano da linha CRI → UnixNano.
// Fallback pro relógio local se o parse falhar.
func parseCRITime(s string) int64 {
	if tt, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return tt.UnixNano()
	}
	return time.Now().UnixNano()
}

// inodeOf extrai o inode do FileInfo (detecção de rotação). 0 se indisponível.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// deriveK8sServiceName tenta extrair o nome do "dono" a partir do nome do pod:
//   backend-8b9fdc855-7vpm2 → backend   (Deployment: <name>-<rs>-<pod>)
//   postgres-0              → postgres  (StatefulSet: <name>-<ordinal>)
//   telvyn-agent-xk2p9      → telvyn-agent (DaemonSet/RS: 1 sufixo)
// Heurística — service.name é secundário (a view de logs de pod filtra por
// namespace+pod); serve só pra agrupar logs por serviço na UI.
func deriveK8sServiceName(pod string) string {
	segs := strings.Split(pod, "-")
	if len(segs) >= 2 {
		last := segs[len(segs)-1]
		switch {
		case isAllDigits(last):
			return sanitizeName(strings.Join(segs[:len(segs)-1], "-"))
		case len(segs) >= 3 && looksLikeHash(last) && looksLikeHash(segs[len(segs)-2]):
			return sanitizeName(strings.Join(segs[:len(segs)-2], "-"))
		case looksLikeHash(last):
			return sanitizeName(strings.Join(segs[:len(segs)-1], "-"))
		}
	}
	return sanitizeName(pod)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// looksLikeHash: 4-10 chars [a-z0-9] com ao menos um dígito (hash de
// ReplicaSet / sufixo aleatório de pod).
func looksLikeHash(s string) bool {
	if len(s) < 4 || len(s) > 10 {
		return false
	}
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z':
		default:
			return false
		}
	}
	return hasDigit
}
