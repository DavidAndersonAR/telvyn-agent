// http.go — OTLP/HTTP receiver (porta 4318 por default). Complementa o
// receiver gRPC em server.go atendendo clientes que não podem (ou não
// querem) falar gRPC:
//
//   - Browsers via OTel SDK Web (CORS habilitado).
//   - Node.js sem grpc-js (apenas fetch + protobuf).
//   - Python/Ruby sem dependência de gRPC.
//   - curl/CLI tooling em testes ad-hoc.
//
// Endpoints aceitos:
//
//   - POST /v1/traces   — ExportTraceServiceRequest
//   - POST /v1/metrics  — ExportMetricsServiceRequest  (descartado:
//                          backend ainda não consome OTLP metrics; aceitamos
//                          200 OK pra não quebrar SDKs configurados com
//                          MeterProvider)
//   - POST /v1/logs     — ExportLogsServiceRequest     (idem)
//
// Content-Type aceitos:
//
//   - application/x-protobuf  — binário, padrão SDK
//   - application/json        — protojson, conveniente pra browser/fetch
//
// Compressão Content-Encoding: aceita gzip (transparente).
//
// CORS: por default Allow-Origin "*" pra simplificar dogfood. Operador pode
// restringir via ISPWATCH_OTLP_HTTP_CORS_ORIGINS=csv,list. Headers/methods
// liberados o suficiente pra OTel Web SDK funcionar sem ajustes.
//
// Sem TLS: assume-se que o caminho cliente→agent é confiável (mesmo nó via
// hostPort, ou cluster interno). O hop agent→backend continua com mTLS.

package otlp

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracedatapb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	// DefaultHTTPListenAddr — porta padrão do OTLP/HTTP per spec.
	DefaultHTTPListenAddr = "0.0.0.0:4318"

	// DefaultMaxBodyBytes — cap de 5MB conforme combinado com o backend.
	// SDKs OTel raramente emitem batches > 1MB; 5MB é folga generosa contra
	// envio acidental, e ainda barato pra alocar em memória.
	DefaultMaxBodyBytes = 5 * 1024 * 1024

	// readHeaderTimeout — defesa básica contra slowloris. 5s é folgado pro
	// caso de cliente legítimo com latência alta sem permitir handshake
	// pendurar conexão indefinidamente.
	readHeaderTimeout = 5 * time.Second
)

// HTTPReceiver é o server HTTP que aceita exports OTLP via JSON ou protobuf.
// Compartilha o mesmo SpanSink do receiver gRPC: tudo cai no Forwarder único
// e segue pelo StreamSpans pro backend.
type HTTPReceiver struct {
	addr         string
	sink         SpanSink
	maxBodyBytes int64
	corsOrigins  []string // nil/empty = "*"
	log          *slog.Logger

	server *http.Server

	// Self-metric counters. Atomic pra evitar lock no hot path. Drenados via
	// Stats() pelo publisher em main.go (pattern idêntico ao ebpf
	// LostSamples).
	tracesAccepted  atomic.Int64
	metricsAccepted atomic.Int64 // metrics endpoint hits (not data points)
	logsAccepted    atomic.Int64
	requestsTotal   atomic.Int64
	requests2xx     atomic.Int64
	requests4xx     atomic.Int64
	requests5xx     atomic.Int64
	spansAccepted   atomic.Int64

	// Per-endpoint request counters indexed por (endpoint, statusBucket).
	endpointMu       sync.Mutex
	endpointRequests map[endpointKey]int64
}

type endpointKey struct {
	Endpoint string
	Status   string // "2xx", "4xx", "5xx"
}

// NewHTTPReceiver constrói o receiver. addr vazio usa DefaultHTTPListenAddr;
// maxBody <= 0 usa DefaultMaxBodyBytes. corsOrigins vazio ou "*" libera
// qualquer origem (útil pra dev/dogfood). Em produção restrita, passe lista
// explícita ["https://app.ispwatch.example.com"].
func NewHTTPReceiver(addr string, sink SpanSink, log *slog.Logger, maxBody int64, corsOrigins []string) *HTTPReceiver {
	if addr == "" {
		addr = DefaultHTTPListenAddr
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	// Normaliza: ["*"] e [] equivalem ao mesmo comportamento (wildcard).
	if len(corsOrigins) == 1 && strings.TrimSpace(corsOrigins[0]) == "*" {
		corsOrigins = nil
	}
	return &HTTPReceiver{
		addr:             addr,
		sink:             sink,
		maxBodyBytes:     maxBody,
		corsOrigins:      corsOrigins,
		log:              log.With("component", "otlp-http"),
		endpointRequests: make(map[endpointKey]int64),
	}
}

// Start abre listener e roda até ctx ser cancelado. Erros de bind retornam
// imediato; erros de Serve (post-listen) são logados como warning porque o
// gRPC continua válido mesmo se HTTP quebrar.
func (h *HTTPReceiver) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", h.handleTraces)
	mux.HandleFunc("/v1/metrics", h.handleMetrics)
	mux.HandleFunc("/v1/logs", h.handleLogs)
	// Healthcheck simples — útil pro Helm chart probar antes de marcar pod
	// como ready. Sem CORS porque é uso interno.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	lis, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("otlp http listen %s: %w", h.addr, err)
	}

	h.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	h.log.Info("otlp http receiver listening",
		"addr", h.addr,
		"max_body_bytes", h.maxBodyBytes,
		"cors_origins", h.corsOriginsForLog(),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := h.server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		h.log.Info("otlp http receiver shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.server.Shutdown(shutdownCtx); err != nil {
			h.log.Warn("otlp http graceful shutdown failed", "err", err)
		}
		return nil
	case err := <-errCh:
		if err != nil {
			h.log.Error("otlp http serve failed", "err", err)
		}
		return err
	}
}

func (h *HTTPReceiver) corsOriginsForLog() string {
	if len(h.corsOrigins) == 0 {
		return "*"
	}
	return strings.Join(h.corsOrigins, ",")
}

// --- Handlers ---------------------------------------------------------------

func (h *HTTPReceiver) handleTraces(w http.ResponseWriter, r *http.Request) {
	h.serveOTLP(w, r, "/v1/traces", func(body []byte, ct string) (int, error) {
		req := &tracepb.ExportTraceServiceRequest{}
		if err := unmarshalOTLP(body, ct, req); err != nil {
			return http.StatusBadRequest, fmt.Errorf("decode trace request: %w", err)
		}
		n := h.convertAndPush(req)
		h.spansAccepted.Add(int64(n))
		h.tracesAccepted.Add(1)
		// Response body — OTLP spec quer ExportTraceServiceResponse vazio em
		// sucesso. Para JSON/protobuf usamos "{}" / bytes(0) que ambos
		// decodificam pro mesmo estado: zero partial_success.
		writeOTLPOK(w, ct)
		return http.StatusOK, nil
	})
}

// handleMetrics e handleLogs aceitam e fazem ack mas descartam o payload —
// backend ainda não tem ingestor pra essas vias OTel. Aceitar 200 OK evita
// que SDKs configurados com MeterProvider/LoggerProvider entrem em loop de
// retry e poluam o agent log. Quando o backend ganhar essas pipelines, troca
// a função de descarte por convertAndPush análogo ao de traces.
func (h *HTTPReceiver) handleMetrics(w http.ResponseWriter, r *http.Request) {
	h.serveOTLP(w, r, "/v1/metrics", func(body []byte, ct string) (int, error) {
		_ = body // descartado de propósito
		h.metricsAccepted.Add(1)
		writeOTLPOK(w, ct)
		return http.StatusOK, nil
	})
}

func (h *HTTPReceiver) handleLogs(w http.ResponseWriter, r *http.Request) {
	h.serveOTLP(w, r, "/v1/logs", func(body []byte, ct string) (int, error) {
		_ = body
		h.logsAccepted.Add(1)
		writeOTLPOK(w, ct)
		return http.StatusOK, nil
	})
}

// serveOTLP centraliza: CORS preflight, validação de método/content-type,
// leitura limitada + descompressão gzip, contadores de status e dispatch
// pro handler específico.
func (h *HTTPReceiver) serveOTLP(w http.ResponseWriter, r *http.Request, endpoint string, fn func(body []byte, ct string) (int, error)) {
	h.requestsTotal.Add(1)

	h.applyCORS(w, r)
	if r.Method == http.MethodOptions {
		// Preflight. CORS headers já foram setados; 204 No Content é a
		// convenção (Express, Caddy, Envoy todos respondem assim).
		w.WriteHeader(http.StatusNoContent)
		h.bumpEndpoint(endpoint, http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		h.bumpEndpoint(endpoint, http.StatusMethodNotAllowed)
		return
	}

	ct := normalizeContentType(r.Header.Get("Content-Type"))
	if ct == "" {
		// SDKs OTel sempre setam Content-Type; corpo sem CT é provavelmente
		// um misconfig do cliente. Default pro binário porque é o caminho
		// nativo, mas avisa.
		ct = "application/x-protobuf"
	}

	body, status, err := h.readBody(r)
	if err != nil {
		h.writeError(w, status, err.Error())
		h.bumpEndpoint(endpoint, status)
		return
	}

	status, err = fn(body, ct)
	if err != nil {
		h.log.Warn("otlp http handler error", "endpoint", endpoint, "err", err, "status", status)
		h.writeError(w, status, err.Error())
		h.bumpEndpoint(endpoint, status)
		return
	}
	h.bumpEndpoint(endpoint, status)
}

func (h *HTTPReceiver) applyCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allow := h.allowedOrigin(origin)
	if allow != "" {
		w.Header().Set("Access-Control-Allow-Origin", allow)
		// Se restringimos por lista, indica que a resposta varia por Origin
		// pra evitar caching incorreto em proxies.
		if len(h.corsOrigins) > 0 {
			w.Header().Add("Vary", "Origin")
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization, traceparent, tracestate")
	// 10min de cache no preflight — equilibra "browser não martelando OPTIONS"
	// com "operador troca config CORS sem esperar 24h".
	w.Header().Set("Access-Control-Max-Age", "600")
}

func (h *HTTPReceiver) allowedOrigin(origin string) string {
	if len(h.corsOrigins) == 0 {
		return "*"
	}
	if origin == "" {
		// Sem Origin (curl, server-to-server) não precisa de header — mas
		// devolver "*" facilita probes. Em modo restrito mantemos silêncio
		// pra não disclosar a lista.
		return ""
	}
	for _, allowed := range h.corsOrigins {
		if strings.EqualFold(strings.TrimSpace(allowed), origin) {
			return origin
		}
	}
	return ""
}

// readBody respeita Content-Encoding (gzip) e enforce maxBodyBytes via
// http.MaxBytesReader — devolve 413 se cliente exceder. Sucesso devolve
// bytes prontos pra deserialização.
func (h *HTTPReceiver) readBody(r *http.Request) ([]byte, int, error) {
	// MaxBytesReader trunca + sinaliza erro se body > limite. Aplicamos
	// ANTES da descompressão — gzip-bomb mitigation: cap em bytes wire,
	// não em bytes descomprimidos. Cliente honesto fica abaixo do limite;
	// ataque tentando expandir 5MB em 5GB falha cedo.
	r.Body = http.MaxBytesReader(nil, r.Body, h.maxBodyBytes)
	defer r.Body.Close()

	var src io.Reader = r.Body
	if enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid gzip body: %w", err)
		}
		defer gz.Close()
		src = gz
	} else if enc != "" && enc != "identity" {
		return nil, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content-encoding: %s", enc)
	}

	// Pós-descompressão também tem um cap defensivo (10x maxBodyBytes) pra
	// não escapar do limite original via gzip-bomb caso o cliente passe
	// gzip header com payload muito comprimido. ReadAll vai parar no EOF
	// natural ou no cap.
	postLimit := h.maxBodyBytes * 10
	body, err := io.ReadAll(io.LimitReader(src, postLimit+1))
	if err != nil {
		// MaxBytesReader devolve *http.MaxBytesError (Go 1.19+) que stringifica
		// como "http: request body too large".
		if isMaxBytesErr(err) {
			return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("payload too large (max %d bytes)", h.maxBodyBytes)
		}
		return nil, http.StatusBadRequest, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > postLimit {
		return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("decompressed payload too large (max %d bytes)", postLimit)
	}
	return body, http.StatusOK, nil
}

func isMaxBytesErr(err error) bool {
	if err == nil {
		return false
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return true
	}
	// Pre-1.19 fallback (defesa em profundidade — go.mod garante 1.22+ mas
	// o check é barato).
	return strings.Contains(err.Error(), "request body too large")
}

// --- Encoding helpers -------------------------------------------------------

func normalizeContentType(ct string) string {
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	switch ct {
	case "application/x-protobuf", "application/protobuf":
		return "application/x-protobuf"
	case "application/json":
		return "application/json"
	}
	return ct
}

// unmarshalOTLP desempacota body no proto msg de acordo com ct. Mensagens
// proto v2 (google.golang.org/protobuf) — protojson cuida do schema OTLP
// (snake_case <-> camelCase) sem ajuste manual.
func unmarshalOTLP(body []byte, ct string, msg proto.Message) error {
	switch ct {
	case "application/json":
		// DiscardUnknown: SDKs futuros podem mandar campos novos; melhor
		// aceitar e ignorar do que falhar export inteiro do cliente.
		return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, msg)
	case "application/x-protobuf":
		return proto.Unmarshal(body, msg)
	}
	return fmt.Errorf("unsupported content-type: %s (use application/x-protobuf or application/json)", ct)
}

// writeOTLPOK escreve a resposta de sucesso esperada pelo OTLP/HTTP spec —
// ExportXResponse vazio, codificado no mesmo CT da request. SDKs OTel
// consultam o response body pra detectar partial_success; resposta vazia
// = "tudo aceito".
func writeOTLPOK(w http.ResponseWriter, ct string) {
	switch ct {
	case "application/json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	default:
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		// ExportTraceServiceResponse{} serializa em 0 bytes — válido.
	}
}

func (h *HTTPReceiver) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

func (h *HTTPReceiver) bumpEndpoint(endpoint string, status int) {
	bucket := statusBucket(status)
	switch bucket {
	case "2xx":
		h.requests2xx.Add(1)
	case "4xx":
		h.requests4xx.Add(1)
	case "5xx":
		h.requests5xx.Add(1)
	}
	h.endpointMu.Lock()
	h.endpointRequests[endpointKey{Endpoint: endpoint, Status: bucket}]++
	h.endpointMu.Unlock()
}

func statusBucket(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 200:
		return "2xx"
	}
	return "other"
}

// --- Span conversion --------------------------------------------------------

// convertAndPush reusa exatamente a mesma lógica do receiver gRPC. Mantemos
// duplicado em uma helper pequena pra não acoplar a interface gRPC Server à
// HTTP — o (Receiver).Export tem signature gRPC-specific (ctx, *Req) →
// (*Resp, error). Helper interna abaixo aceita o request bruto.
func (h *HTTPReceiver) convertAndPush(req *tracepb.ExportTraceServiceRequest) int {
	if req == nil {
		return 0
	}
	spans := convertResourceSpans(req.ResourceSpans)
	if len(spans) > 0 && h.sink != nil {
		h.sink.Push(spans)
	}
	return len(spans)
}

// convertResourceSpans extrai o que o (Receiver).Export gRPC faz inline —
// reaproveitado pelos dois receivers. Mantém o comportamento idêntico:
// service.name a partir de resource attrs, namespace/pod populados quando
// presentes, atributos resource mesclados sem sobrescrever os do span.
func convertResourceSpans(resourceSpans []*resourceSpansAlias) []*collectorv1.Span {
	// Trick: o tipo real é tracepb.ResourceSpans; alias é definido abaixo
	// pra deixar a função importável sem expor o pacote OTel proto pra
	// callers internos que só pensem em collectorv1.Span.
	var spans []*collectorv1.Span
	for _, rs := range resourceSpans {
		var resAttrs map[string]string
		if rs.Resource != nil {
			resAttrs = flattenAttrs(rs.Resource.GetAttributes())
		} else {
			resAttrs = map[string]string{}
		}
		serviceName := resAttrs["service.name"]
		namespace := resAttrs["k8s.namespace.name"]
		pod := resAttrs["k8s.pod.name"]
		if serviceName == "" {
			serviceName = pod
		}
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				cs := &collectorv1.Span{
					TraceId:       hex.EncodeToString(s.TraceId),
					SpanId:        hex.EncodeToString(s.SpanId),
					ParentSpanId:  hex.EncodeToString(s.ParentSpanId),
					ServiceName:   serviceName,
					Name:          s.Name,
					Kind:          int32(s.Kind),
					StartUnixNano: int64(s.StartTimeUnixNano),
					EndUnixNano:   int64(s.EndTimeUnixNano),
					Namespace:     namespace,
					Pod:           pod,
					Attributes:    flattenAttrs(s.Attributes),
				}
				if s.Status != nil {
					cs.StatusCode = int32(s.Status.Code)
					cs.StatusMessage = s.Status.Message
				}
				for k, v := range resAttrs {
					if _, ok := cs.Attributes[k]; !ok {
						cs.Attributes[k] = v
					}
				}
				spans = append(spans, cs)
			}
		}
	}
	return spans
}

// resourceSpansAlias é apenas pra clarear a função acima — não exporta tipo
// novo, apenas evita repetir tracedatapb.ResourceSpans em loop interno. O Go
// resolve o alias em compile-time sem custo. ResourceSpans vive em
// otlp/trace/v1 (data), não em otlp/collector/trace/v1 (service RPC).
type resourceSpansAlias = tracedatapb.ResourceSpans

// --- Self-metrics export ----------------------------------------------------

// HTTPStats é um snapshot consumido pelo publisher de self-metrics em main.
// Mantemos contadores cumulativos (counter-style) e let o dashboard aplicar
// rate() — mesmo contrato dos contadores de ebpf_lost_samples.
type HTTPStats struct {
	RequestsTotal   int64
	Requests2xx     int64
	Requests4xx     int64
	Requests5xx     int64
	SpansAccepted   int64
	TracesAccepted  int64
	MetricsAccepted int64
	LogsAccepted    int64
	PerEndpoint     map[string]int64 // key "endpoint:bucket" → count
}

// Stats devolve snapshot atômico. Cópia barata; chamado a cada 30s pelo
// publisher.
func (h *HTTPReceiver) Stats() HTTPStats {
	h.endpointMu.Lock()
	per := make(map[string]int64, len(h.endpointRequests))
	for k, v := range h.endpointRequests {
		per[k.Endpoint+":"+k.Status] = v
	}
	h.endpointMu.Unlock()
	return HTTPStats{
		RequestsTotal:   h.requestsTotal.Load(),
		Requests2xx:     h.requests2xx.Load(),
		Requests4xx:     h.requests4xx.Load(),
		Requests5xx:     h.requests5xx.Load(),
		SpansAccepted:   h.spansAccepted.Load(),
		TracesAccepted:  h.tracesAccepted.Load(),
		MetricsAccepted: h.metricsAccepted.Load(),
		LogsAccepted:    h.logsAccepted.Load(),
		PerEndpoint:     per,
	}
}

// ParseCORSOrigins é helper pro caller (main.go) — split CSV em []string e
// trim. Vazio devolve nil (=> wildcard). Centralizado aqui pra evitar drift.
func ParseCORSOrigins(csv string) []string {
	csv = strings.TrimSpace(csv)
	if csv == "" || csv == "*" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParsePortOrDefault — helper compat com pattern dos outros componentes
// (DefaultListenAddr).
func ParsePortOrDefault(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return DefaultHTTPListenAddr
	}
	// Aceita "4318" ou "0.0.0.0:4318".
	if _, _, err := net.SplitHostPort(port); err == nil {
		return port
	}
	if _, err := strconv.Atoi(port); err == nil {
		return "0.0.0.0:" + port
	}
	return port
}
