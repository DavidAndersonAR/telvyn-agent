// logs.go — bridge journald → backend HTTP logs export.
//
// Pattern espelhado do Forwarder de spans (forwarder.go) só que:
//   • Não passa por gRPC StreamSpans — saída é direto via HTTP POST
//     pro endpoint /api/collector/v1/logs do Quarkus (porta 8444 mTLS).
//   • Payload é JSON simples (1 array de records). Optamos pra JSON sobre
//     OTLP/proto pra evitar pull de dep nova no backend Quarkus — o REST
//     resource consome direto via Jackson. Mantemos as semantics OTLP
//     (severity_number, body, attributes) e os field names canônicos.
//   • Batch send a cada LogsBatchFlushInterval (2s) OU assim que o buffer
//     junta um batch cheio (LogsBatchMaxRecords) — o que vier primeiro. O
//     gatilho por tamanho (flushSignal) é o que absorve rajada: sem ele, uma
//     rajada só drena no próximo tick, e o buffer estoura à toa mesmo com o
//     backend ocioso.
//
// Sem WAL: logs são best-effort. Buffer cheio (> LogsBufferMaxRecords) =
// dropa os mais antigos (FIFO), conta em droppedTotal (agent_logs_dropped_total)
// e loga um WARN agregado no máx 1×/s (pra uma rajada de N drops não virar N
// linhas de log).

package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// LogsBatchMaxRecords — max records por POST E limiar do flush por tamanho:
	// quando o buffer junta esse tanto, o Push acorda o flusher na hora (em vez
	// de esperar o tick). Mantemos baixo (100) pra evitar requests grandes;
	// backend persiste por linha mesmo, então não compensa empacotar 1000.
	LogsBatchMaxRecords = 100

	// LogsBufferMaxRecords — teto do buffer em memória (rede de segurança pra
	// quando o backend está lento/fora e o flush não drena a tempo). Acima
	// disso, dropa os mais antigos. 40× o batch (~4MB com linhas típicas <1KB)
	// dá folga de rajada suficiente sem virar risco de OOM. Era 4× (400), curto
	// demais: só ~2s de absorção a 200 linhas/s.
	LogsBufferMaxRecords = 40 * LogsBatchMaxRecords

	// LogsBatchFlushInterval — flush periódico mesmo com pouco volume,
	// pra UI ver logs com latência ≤ 2s.
	LogsBatchFlushInterval = 2 * time.Second

	// LogsRequestTimeout — request HTTP tem cap de 10s. Mais que isso é
	// problema de saúde do backend; melhor falhar rápido e dropar batch.
	LogsRequestTimeout = 10 * time.Second
)

// LogRecord é o shape interno que callers (journald reader) entregam ao
// LogsExporter. Conversão pra OTLP é feita dentro do Push em batch.
type LogRecord struct {
	TimestampUnixNano int64
	ServiceName       string            // mapeia pra Resource.attributes service.name
	Hostname          string            // host.name
	SeverityNumber    int               // OTel severity 1-24
	SeverityText      string            // "INFO" | "WARN" | "ERROR" | ...
	Body              string            // mensagem
	TraceID           string            // hex32, vazio se a linha não trouxe — liga o log ao trace
	SpanID            string            // hex16, vazio se ausente
	Attributes        map[string]string // attrs do log record
}

// LogsExporter agrega LogRecords, faz batch e POST OTLP pro backend.
// Single struct atomicamente safe; instanciado uma vez no main.
type LogsExporter struct {
	collectorID string
	endpoint    string // ex: https://quarkus:8444 (modo mTLS)
	tenantID    string
	httpClient  *http.Client
	log         *slog.Logger

	// ingest != nil ⇒ modo certless (Datadog-style): em vez do POST mTLS pro
	// /api/collector/v1/logs, cada batch sai como OTLP JSON + Bearer pro
	// gateway /api/ingest/v1/logs. Toda a maquinaria de buffer/flush/overflow
	// é reusada — só o transporte do sendBatch muda.
	ingest *IngestExporter

	mu  sync.Mutex
	buf []LogRecord

	// flushSignal acorda o Run pra flush imediato quando o buffer junta um
	// batch cheio (LogsBatchMaxRecords). Buffered(1): coalesce — uma rajada de
	// N pushes gera no máx 1 sinal pendente, e cada flush drena o buffer todo.
	flushSignal chan struct{}

	// Counters — drenados pelo publisher de self-metrics.
	linesTotal   atomic.Int64
	bytesTotal   atomic.Int64
	droppedTotal atomic.Int64
	sentBatches  atomic.Int64
	sendFailures atomic.Int64

	// Rate-limit do WARN de overflow: agrega os drops e loga no máx 1×/s.
	overflowPending  atomic.Int64
	lastOverflowWarn atomic.Int64
}

// NewLogsExporter constrói o exporter. endpoint = https://host:port (sem
// path). certPath/keyPath/trustPath = mesmos paths do gRPC e config pull.
// Se algum path é vazio, ativa InsecureSkipVerify pra dev sem cert (o
// servidor com mTLS rejeita o handshake — caller verá no log).
func NewLogsExporter(endpoint, tenantID, collectorID string, certPath, keyPath, trustPath string, log *slog.Logger) (*LogsExporter, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" && keyPath != "" {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert (%s, %s): %w", certPath, keyPath, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	if trustPath != "" {
		pem, err := os.ReadFile(trustPath)
		if err != nil {
			return nil, fmt.Errorf("read trust bundle %s: %w", trustPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust bundle %s contained no PEM certs", trustPath)
		}
		tlsCfg.RootCAs = pool
	}
	return &LogsExporter{
		collectorID: collectorID,
		endpoint:    strings.TrimRight(endpoint, "/"),
		tenantID:    tenantID,
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   LogsRequestTimeout,
		},
		flushSignal: make(chan struct{}, 1),
		log:         log.With("component", "otlp-logs"),
	}, nil
}

// NewIngestLogsExporter constrói um LogsExporter no modo certless: os batches
// são enviados via ingest.PostLogs (OTLP JSON + Bearer) em vez do canal mTLS.
// Reusa Push/Run/flush/overflow/Stats do exporter mTLS.
func NewIngestLogsExporter(ingest *IngestExporter, log *slog.Logger) *LogsExporter {
	return &LogsExporter{
		ingest:      ingest,
		httpClient:  &http.Client{Timeout: LogsRequestTimeout},
		flushSignal: make(chan struct{}, 1),
		log:         log.With("component", "otlp-logs-ingest"),
	}
}

// Push adiciona records ao buffer interno. Nunca bloqueia (o tailer não pode
// travar): acima de LogsBufferMaxRecords dropa os mais antigos (FIFO). Ao juntar
// um batch cheio, sinaliza o Run pra flush imediato — sem esperar o ticker.
func (e *LogsExporter) Push(rec LogRecord) {
	e.mu.Lock()
	e.buf = append(e.buf, rec)
	e.linesTotal.Add(1)
	e.bytesTotal.Add(int64(len(rec.Body)))
	var drop int
	if len(e.buf) > LogsBufferMaxRecords {
		drop = len(e.buf) - LogsBufferMaxRecords
		e.buf = e.buf[drop:]
	}
	buffered := len(e.buf)
	full := buffered >= LogsBatchMaxRecords
	e.mu.Unlock()

	// Flush por tamanho: non-blocking. Se já há um flush sinalizado, ignora
	// (o flush drena o buffer todo de qualquer forma).
	if full {
		select {
		case e.flushSignal <- struct{}{}:
		default:
		}
	}
	if drop > 0 {
		e.droppedTotal.Add(int64(drop))
		e.warnOverflow(drop, buffered)
	}
}

// warnOverflow loga o overflow no máx 1×/s, agregando quantos records foram
// dropados no intervalo — uma rajada de 400 drops vira 1 linha, não 400. O
// número exato de perdas fica em droppedTotal (fonte de verdade pro alerta).
func (e *LogsExporter) warnOverflow(drop, buffered int) {
	e.overflowPending.Add(int64(drop))
	now := time.Now().UnixNano()
	last := e.lastOverflowWarn.Load()
	if now-last < int64(time.Second) {
		return
	}
	if !e.lastOverflowWarn.CompareAndSwap(last, now) {
		return // outra goroutine já pegou a janela deste segundo
	}
	dropped := e.overflowPending.Swap(0)
	e.log.Warn("logs buffer overflow, dropped oldest",
		"dropped", dropped, "buffered", buffered, "cap", LogsBufferMaxRecords)
}

// Run loops flushing periodicamente até ctx ser cancelado. Best-effort
// drain final no shutdown.
func (e *LogsExporter) Run(ctx context.Context) {
	ticker := time.NewTicker(LogsBatchFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.flush(context.Background()) // best-effort
			return
		case <-ticker.C:
			e.flush(ctx)
		case <-e.flushSignal:
			// Buffer juntou um batch cheio antes do tick — drena já.
			e.flush(ctx)
		}
	}
}

// flush drena o buffer em batches de até LogsBatchMaxRecords e POSTa cada
// batch. Falha de POST não recoloca records no buffer — best-effort.
func (e *LogsExporter) flush(ctx context.Context) {
	for {
		e.mu.Lock()
		if len(e.buf) == 0 {
			e.mu.Unlock()
			return
		}
		n := len(e.buf)
		if n > LogsBatchMaxRecords {
			n = LogsBatchMaxRecords
		}
		batch := make([]LogRecord, n)
		copy(batch, e.buf[:n])
		e.buf = e.buf[n:]
		e.mu.Unlock()

		if err := e.sendBatch(ctx, batch); err != nil {
			e.sendFailures.Add(1)
			e.log.Warn("logs batch send failed", "count", len(batch), "err", err)
			// não retry — dropamos batch e seguimos. Logs perdidos == OK.
			return
		}
		e.sentBatches.Add(1)
	}
}

// logBatchWire é o shape JSON enviado em cada POST. Campos espelham OTLP
// LogRecord sem o overhead protobuf — backend Quarkus parseia via Jackson
// sem deps OTel extras. Quando precisarmos full OTLP (clientes 3rd party
// mandando ExportLogsServiceRequest), trocar pra OTLP proto sem mudar a
// rota: este é só o canal interno agent→backend.
type logBatchWire struct {
	CollectorID string         `json:"collector_id"`
	Hostname    string         `json:"hostname"`
	Records     []logRecordWire `json:"records"`
}

type logRecordWire struct {
	TimeUnixNano   int64             `json:"time_unix_nano"`
	ServiceName    string            `json:"service_name"`
	SeverityNumber int               `json:"severity_number"`
	SeverityText   string            `json:"severity_text"`
	Body           string            `json:"body"`
	TraceID        string            `json:"trace_id,omitempty"`
	SpanID         string            `json:"span_id,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// sendBatch monta o JSON batch e POSTa.
func (e *LogsExporter) sendBatch(ctx context.Context, batch []LogRecord) error {
	if e.ingest != nil {
		return e.ingest.PostLogs(ctx, batch)
	}
	if e.endpoint == "" {
		return fmt.Errorf("logs exporter endpoint not configured")
	}
	wire := logBatchWire{
		CollectorID: e.collectorID,
		Records:     make([]logRecordWire, 0, len(batch)),
	}
	for _, r := range batch {
		if wire.Hostname == "" && r.Hostname != "" {
			wire.Hostname = r.Hostname
		}
		wire.Records = append(wire.Records, logRecordWire{
			TimeUnixNano:   r.TimestampUnixNano,
			ServiceName:    r.ServiceName,
			SeverityNumber: r.SeverityNumber,
			SeverityText:   r.SeverityText,
			Body:           r.Body,
			TraceID:        r.TraceID,
			SpanID:         r.SpanID,
			Attributes:     r.Attributes,
		})
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("marshal logs request: %w", err)
	}

	// Endpoint: /api/collector/v1/logs (com query params do mTLS filter).
	url := fmt.Sprintf("%s/api/collector/v1/logs?tenant_id=%s&collector_id=%s",
		e.endpoint, e.tenantID, e.collectorID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("backend %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// LogsStats — snapshot consumido pelo publisher de self-metrics.
type LogsStats struct {
	LinesTotal   int64
	BytesTotal   int64
	DroppedTotal int64
	SentBatches  int64
	SendFailures int64
}

func (e *LogsExporter) Stats() LogsStats {
	return LogsStats{
		LinesTotal:   e.linesTotal.Load(),
		BytesTotal:   e.bytesTotal.Load(),
		DroppedTotal: e.droppedTotal.Load(),
		SentBatches:  e.sentBatches.Load(),
		SendFailures: e.sendFailures.Load(),
	}
}
