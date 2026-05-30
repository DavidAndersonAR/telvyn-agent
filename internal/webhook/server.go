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
	"os"
	"strings"
	"sync"
	"time"
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
type Config struct {
	ListenAddr        string
	CertDir           string
	BackendURL        string // ex: https://quarkus:8444
	TenantID          string
	ClientCert        string // mTLS pra falar com backend
	ClientKey         string
	TrustBundle       string
	AgentImage        string // imagem que o initContainer usa pra copiar o jar
	OtlpEndpointEnv   string // valor de OTEL_EXPORTER_OTLP_ENDPOINT injetado
	Log               *slog.Logger
}

// Server é o webhook HTTPS que responde AdmissionReview do api-server.
type Server struct {
	cfg    Config
	mu     sync.RWMutex
	enable map[string]struct{} // "ns/pod" → presente quando ativado em mode=java_javaagent
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
		cfg.AgentImage = "ispwatch-agent:latest"
	}
	if cfg.OtlpEndpointEnv == "" {
		cfg.OtlpEndpointEnv = "http://$(NODE_IP):4317"
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
	Mode      string `json:"mode"`
}
type instrResp struct {
	Entries []instrEntry `json:"entries"`
}

func (s *Server) poll(ctx context.Context) {
	collectorID := os.Getenv("ISPWATCH_COLLECTOR_ID")
	url := strings.TrimRight(s.cfg.BackendURL, "/") +
		"/api/collector/v1/k8s/instrumentation?tenant_id=" + s.cfg.TenantID +
		"&collector_id=" + collectorID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.cfg.Log.Warn("webhook poll: new req failed", "err", err)
		return
	}
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
	next := make(map[string]struct{}, len(r.Entries))
	for _, e := range r.Entries {
		if e.Mode == "java_javaagent" {
			next[e.Namespace+"/"+e.Pod] = struct{}{}
		}
	}
	s.mu.Lock()
	s.enable = next
	s.mu.Unlock()
	s.cfg.Log.Debug("webhook poll: list updated", "java_targets", len(next))
}

func (s *Server) setupClient() error {
	cert, err := tls.LoadX509KeyPair(s.cfg.ClientCert, s.cfg.ClientKey)
	if err != nil {
		return fmt.Errorf("webhook backend client cert: %w", err)
	}
	caPool, err := loadCABundle(s.cfg.TrustBundle)
	if err != nil {
		return err
	}
	s.client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
			},
		},
	}
	return nil
}

// shouldInject — pod (ns, name) está no enable map?
func (s *Server) shouldInject(ns, name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.enable[ns+"/"+name]
	return ok
}
