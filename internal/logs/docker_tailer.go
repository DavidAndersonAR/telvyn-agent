// docker_tailer.go — Docker container log tailer. Descobre containers running
// via Docker SDK, taila o json-file log de cada um, parseia, e envia pro OTLP
// LogsExporter existente (mesmo pipeline que journald).
//
// Lifecycle:
//   - Discovery loop (10s): lista containers via Docker daemon, spawna readers
//     pra novos containers, para readers de containers removidos.
//   - Per-container JSONFileReader: polling 100ms, parse json-file format,
//     rate limit, cursor persistence.
//   - Bridge goroutine: drena channel de LogEntry e converte pra otlp.LogRecord
//     via Push() no exporter.
//
// Ativado via ISPWATCH_LOGS_DOCKER=1 (default off).
package logs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	"github.com/ispwatch/collector/internal/otlp"
)

const (
	// discoveryInterval — frequência com que relista containers do daemon.
	discoveryInterval = 10 * time.Second

	// cursorFlushInterval — frequência de flush dos cursors pra disco.
	cursorFlushInterval = 5 * time.Second

	// defaultRateLimitBytesPerSec — limite default por container (1MB/s).
	// Override via ISPWATCH_DOCKER_LOGS_RATE_LIMIT_BYTES env.
	defaultRateLimitBytesPerSec = 1 * 1024 * 1024

	// dockerContainersDir — path padrão dos logs do json-file driver.
	dockerContainersDir = "/var/lib/docker/containers"

	// entryChannelSize — buffer do channel entre readers e bridge.
	entryChannelSize = 4096
)

// DockerLogsTailer coordena a descoberta de containers e seus readers.
type DockerLogsTailer struct {
	cli      *client.Client
	exporter *otlp.LogsExporter
	cursors  *CursorStore
	hostname string
	log      *slog.Logger

	rateLimitBytes int64
	entryCh        chan LogEntry
	multiline      bool // junta mensagem de várias linhas (ver multiline.go)

	mu      sync.Mutex
	readers map[string]*readerHandle // container_id → handle

	// Stats.
	linesTotal   atomic.Int64
	droppedTotal atomic.Int64
}

// readerHandle mantém o state de um reader ativo.
type readerHandle struct {
	reader *JSONFileReader
	done   chan struct{} // close pra parar o reader
}

// NewDockerLogsTailer cria o tailer. Conecta ao Docker daemon via socket.
// Retorna erro se o daemon não está acessível (host sem Docker).
func NewDockerLogsTailer(
	exporter *otlp.LogsExporter,
	cursorPath string,
	log *slog.Logger,
) (*DockerLogsTailer, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	// Ping pra falhar cedo se o daemon não responde.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cli.Ping(ctx); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("docker ping: %w", err)
	}

	hostname, _ := os.Hostname()

	rateLimit := int64(defaultRateLimitBytesPerSec)
	if v := os.Getenv("ISPWATCH_DOCKER_LOGS_RATE_LIMIT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			rateLimit = n
		}
	}

	return &DockerLogsTailer{
		cli:            cli,
		exporter:       exporter,
		cursors:        NewCursorStore(cursorPath, log),
		hostname:       hostname,
		log:            log.With("component", "docker-logs-tailer"),
		rateLimitBytes: rateLimit,
		entryCh:        make(chan LogEntry, entryChannelSize),
		multiline:      os.Getenv("ISPWATCH_LOGS_MULTILINE") != "0",
		readers:        make(map[string]*readerHandle),
	}, nil
}

// Run inicia o tailer. Bloqueia até ctx ser cancelado.
func (t *DockerLogsTailer) Run(ctx context.Context) {
	t.log.Info("docker logs tailer starting",
		"rate_limit_bytes_per_sec", t.rateLimitBytes,
		"containers_dir", dockerContainersDir)

	// Bridge: LogEntry → OTLP LogRecord.
	go t.bridge(ctx)

	// Cursor flush loop.
	go t.cursorFlushLoop(ctx)

	// Discovery loop.
	// Primeira discovery imediata, depois a cada intervalo.
	t.discover()

	ticker := time.NewTicker(discoveryInterval)
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

// Stats retorna contadores pra self-metrics.
type DockerLogsStats struct {
	LinesTotal   int64
	DroppedTotal int64
}

func (t *DockerLogsTailer) Stats() DockerLogsStats {
	return DockerLogsStats{
		LinesTotal:   t.linesTotal.Load(),
		DroppedTotal: t.droppedTotal.Load(),
	}
}

// bridge drena o channel de entries e converte pro exporter OTLP.
//
// O agregador de multilinha vive AQUI (uma goroutine só, sem trava) e é chaveado
// por container: o channel é compartilhado, então as linhas de containers
// diferentes chegam intercaladas e não podem colar umas nas outras.
func (t *DockerLogsTailer) bridge(ctx context.Context) {
	var agg *multilineAggregator
	if t.multiline {
		agg = newMultilineAggregator(t.exporter.Push)
	}
	// Fecha mensagem parada: sem isto, a última de um container quieto dormiria
	// no buffer. No CRI quem faz esse papel é o poll do reader.
	tick := time.NewTicker(criPollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			if agg != nil {
				agg.FlushAll()
			}
			return
		case <-tick.C:
			if agg != nil {
				agg.Tick(time.Now())
			}
		case entry, ok := <-t.entryCh:
			if !ok {
				if agg != nil {
					agg.FlushAll()
				}
				return
			}
			t.linesTotal.Add(1)

			sevNum, sevText := streamToSeverity(entry.Stream)
			// Só texto puro. Este tailer não interpreta JSON, e varrer o corpo
			// de um log estruturado pegaria a palavra "ERROR" de dentro da
			// mensagem como se fosse o nível.
			if !isJSONLine(entry.Body) {
				if n, txt, ok := plainTextSeverity(entry.Body); ok {
					sevNum, sevText = n, txt
				}
			}

			attrs := map[string]string{
				"container_id":   entry.Meta.ContainerID,
				"container_name": entry.Meta.ContainerName,
				"service_name":   entry.Meta.ServiceName,
				"stream":         entry.Stream,
				"image":          entry.Meta.ImageName,
				"source":         "docker",
			}

			rec := otlp.LogRecord{
				TimestampUnixNano: entry.TimestampUnixNano,
				ServiceName:       entry.Meta.ServiceName,
				Hostname:          t.hostname,
				SeverityNumber:    sevNum,
				SeverityText:      sevText,
				Body:              entry.Body,
				Attributes:        attrs,
			}
			if agg != nil {
				agg.Add(entry.Meta.ContainerID, rec, time.Now())
				continue
			}
			t.exporter.Push(rec)
		}
	}
}

// discover lista containers running e reconcilia com readers ativos.
func (t *DockerLogsTailer) discover() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	containers, err := t.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		t.log.Warn("docker container list failed", "err", err)
		return
	}

	// Build set of running container IDs.
	running := make(map[string]container.Summary, len(containers))
	for _, c := range containers {
		running[c.ID] = c
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Stop readers for containers that are no longer running.
	for id, h := range t.readers {
		if _, ok := running[id]; !ok {
			t.log.Debug("container gone, stopping reader", "container_id", id[:12])
			close(h.done)
			delete(t.readers, id)
		}
	}

	// Start readers for new containers.
	for id, c := range running {
		if _, ok := t.readers[id]; ok {
			continue // already tailing
		}

		logPath := filepath.Join(dockerContainersDir, id, id+"-json.log")
		if _, err := os.Stat(logPath); err != nil {
			// Log file doesn't exist (maybe different log driver).
			continue
		}

		meta := ContainerMeta{
			ContainerID:   id,
			ContainerName: containerName(c),
			ServiceName:   deriveServiceName(c),
			ImageName:     c.Image,
		}

		done := make(chan struct{})
		reader := NewJSONFileReader(logPath, meta, t.cursors, t.rateLimitBytes, t.entryCh, t.log)

		t.readers[id] = &readerHandle{reader: reader, done: done}

		t.log.Debug("starting reader for container",
			"container_id", id[:12],
			"name", meta.ContainerName,
			"service", meta.ServiceName)

		go reader.Run(done)
	}
}

// cursorFlushLoop persiste cursors periodicamente e coleta dropped stats.
func (t *DockerLogsTailer) cursorFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(cursorFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.flushAllCursors()
			t.cursors.Flush()
			return
		case <-ticker.C:
			t.flushAllCursors()
			t.cursors.Flush()
			t.collectDroppedStats()
		}
	}
}

// flushAllCursors pede a cada reader ativo que salve seu cursor.
func (t *DockerLogsTailer) flushAllCursors() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.readers {
		h.reader.saveCursor()
	}
}

// collectDroppedStats agrega contadores de linhas dropadas dos readers.
func (t *DockerLogsTailer) collectDroppedStats() {
	t.mu.Lock()
	defer t.mu.Unlock()
	var total int64
	for _, h := range t.readers {
		total += h.reader.DroppedLines()
	}
	t.droppedTotal.Store(total)
}

// shutdown para todos os readers e flush final.
func (t *DockerLogsTailer) shutdown() {
	t.log.Info("docker logs tailer shutting down")
	t.mu.Lock()
	for id, h := range t.readers {
		close(h.done)
		delete(t.readers, id)
	}
	t.mu.Unlock()
	// Drain remaining entries.
	close(t.entryCh)
	// Final cursor flush.
	t.cursors.Flush()
	_ = t.cli.Close()
}

// streamToSeverity mapeia o campo "stream" do Docker log pra OTel severity.
//   - "stderr" → WARN (13)
//   - "stdout" → INFO (9)
func streamToSeverity(stream string) (int, string) {
	switch stream {
	case "stderr":
		return 13, "WARN"
	default:
		return 9, "INFO"
	}
}

// deriveServiceName usa labels do compose ou nome do container como fallback.
func deriveServiceName(c container.Summary) string {
	if v := c.Labels["com.docker.compose.service"]; v != "" {
		return sanitizeName(v)
	}
	name := containerName(c)
	if name != "" {
		return sanitizeName(name)
	}
	// Fallback: image name without tag/registry.
	img := c.Image
	if i := strings.LastIndex(img, "/"); i >= 0 {
		img = img[i+1:]
	}
	if i := strings.Index(img, ":"); i >= 0 {
		img = img[:i]
	}
	return sanitizeName(img)
}

// containerName extrai o nome limpo (sem "/" prefix) do container.
func containerName(c container.Summary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return ""
}

// sanitizeName normaliza pra ASCII minúsculo + hífen.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "unknown"
	}
	return out
}
