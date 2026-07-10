// Package webhook implementa o Mutating Admission Webhook que injeta o
// -javaagent OpenTelemetry em pods Java cujo (namespace, pod) esteja
// marcado como mode=java_javaagent na tabela noc_pod_instrumentation
// do backend (controlado pela UI, não pelo manifest do cliente).
//
// Decisões locked:
//
//   - Lista de pods vem do backend (mesma fonte do quarkus scraper).
//     Webhook mantém cache local e revalida a cada 15s. Pra um pod ser
//     instrumentado precisa: estar na lista E ter pelo menos 1 container
//     Java (heurística: image contém 'java'/'jdk'/'temurin'/'openjdk',
//     ou já tem JAVA_TOOL_OPTIONS no env).
//
//   - TLS cert montado em /etc/ispwatch/webhook/{tls.crt,tls.key} via
//     Secret. CA bundle distribuído pro k8s api-server via
//     MutatingWebhookConfiguration.caBundle.
//
//   - Best-effort: erro de lookup do backend → não injeta, deixa o pod
//     subir normal. Webhook nunca bloqueia admissão por falha nossa.
//
//   - Reusa /opt/otel/javaagent.jar já embarcado na imagem do agent.
//     O initContainer injetado usa a mesma imagem do webhook (mesma
//     imagem do DaemonSet) — copia o jar pro emptyDir compartilhado.

package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ispwatch/collector/internal/k8smeta"
)

const (
	// DefaultListenAddr — webhook server bind. K8s API server alcança via
	// Service ClusterIP.
	DefaultListenAddr = ":8443"

	// DefaultCertDir — TLS cert/key montados via Secret.
	DefaultCertDir = "/etc/ispwatch/webhook"

	defaultBackendPollInterval = 15 * time.Second
)

// Config bootstrap pro webhook server.
//
// Modelo certless (igual ao resto do agent ingest): a lista de workloads
// marcados vem do gateway via Bearer token — sem mTLS. Ver scraper quarkus.
type Config struct {
	ListenAddr      string
	CertDir         string
	IngestURL       string // ex: http://backend.ispwatch.svc.cluster.local:8080
	Token           string // Bearer iwI_... (mesmo token do DaemonSet)
	AgentImage      string // imagem que o initContainer usa pra copiar o jar
	OtlpEndpointEnv string // valor de OTEL_EXPORTER_OTLP_ENDPOINT injetado
	OtlpProtocol    string // valor de OTEL_EXPORTER_OTLP_PROTOCOL injetado
	Log             *slog.Logger
}

// Server é o webhook HTTPS que responde AdmissionReview do api-server.
type Server struct {
	cfg    Config
	mu     sync.RWMutex
	enable map[string]struct{} // "ns/workload" → ativado em mode=java_javaagent
	client *http.Client
}

func New(cfg Config) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.CertDir == "" {
		cfg.CertDir = DefaultCertDir
	}
	if cfg.AgentImage == "" {
		cfg.AgentImage = "localhost/telvyn-agent:local"
	}
	if cfg.OtlpEndpointEnv == "" {
		// Em modo ingest o agent só sobe o receptor OTLP/HTTP na :4318.
		cfg.OtlpEndpointEnv = "http://$(NODE_IP):4318"
	}
	if cfg.OtlpProtocol == "" {
		cfg.OtlpProtocol = "http/protobuf"
	}
	return &Server{
		cfg:    cfg,
		enable: make(map[string]struct{}),
	}
}

// Run inicia o poller do backend + HTTPS server. Bloqueia até ctx cancel.
func (s *Server) Run(ctx context.Context) error {
	if err := s.setupClient(); err != nil {
		return err
	}
	go s.pollLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.handleMutate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	cert, err := tls.LoadX509KeyPair(s.cfg.CertDir+"/tls.crt", s.cfg.CertDir+"/tls.key")
	if err != nil {
		return fmt.Errorf("load webhook TLS cert: %w", err)
	}
	srv := &http.Server{
		Addr:    s.cfg.ListenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.cfg.Log.Info("webhook server listening", "addr", s.cfg.ListenAddr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// pollLoop atualiza enable map a cada 15s consultando o backend.
func (s *Server) pollLoop(ctx context.Context) {
	tk := time.NewTicker(defaultBackendPollInterval)
	defer tk.Stop()
	s.poll(ctx) // primeiro tick imediato
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			s.poll(ctx)
		}
	}
}

type instrEntry struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Workload  string `json:"workload"`
	Mode      string `json:"mode"`
}
type instrResp struct {
	Entries []instrEntry `json:"entries"`
}

func (s *Server) poll(ctx context.Context) {
	url := strings.TrimRight(s.cfg.IngestURL, "/") + "/api/ingest/v1/k8s/instrumentation"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.cfg.Log.Warn("webhook poll: new req failed", "err", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	resp, err := s.client.Do(req)
	if err != nil {
		s.cfg.Log.Debug("webhook poll: backend unreachable", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.cfg.Log.Warn("webhook poll: status non-2xx", "status", resp.StatusCode, "body", string(body))
		return
	}
	var r instrResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		s.cfg.Log.Warn("webhook poll: decode failed", "err", err)
		return
	}
	// Chaveia por WORKLOAD (não pod): sobrevive a rollout/restart, igual ao
	// scraper quarkus. O backend já devolve 'workload'; fallback deriva do pod.
	next := make(map[string]struct{}, len(r.Entries))
	for _, e := range r.Entries {
		if e.Mode != "java_javaagent" {
			continue
		}
		wl := e.Workload
		if wl == "" {
			wl = k8smeta.WorkloadOf(e.Pod)
		}
		next[e.Namespace+"/"+wl] = struct{}{}
	}
	s.mu.Lock()
	s.enable = next
	s.mu.Unlock()
	s.cfg.Log.Debug("webhook poll: list updated", "java_targets", len(next))
}

// setupClient — cliente HTTP simples (ingest é HTTP in-cluster + Bearer; sem mTLS).
func (s *Server) setupClient() error {
	s.client = &http.Client{Timeout: 10 * time.Second}
	return nil
}
