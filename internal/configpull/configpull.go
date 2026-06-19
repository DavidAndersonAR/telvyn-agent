// Package configpull implementa o cliente pull-based de config do collector.
//
// Phase 5 — substitui o caminho push (config.reload via gRPC) por polling do
// endpoint HTTP /api/collector/v1/config?since=<v>. Modelo pull-based:
//   - Servidor não sabe quando empurrar; agente decide ritmo via collector.conf
//   - Servidor mantém versão monotônica per-tenant e devolve delta
//   - Agente aplica delta via checks.Runtime.ApplyDelta — sem stop-the-world
//
// Phase 5b — auth migrou de JWT estático (env AGENT_TOKEN) pra mTLS. O cliente
// HTTP usa o MESMO material TLS (client cert + chave + trust bundle) já
// configurado pra gRPC, garantindo identidade de tenant + collector. O server
// (CollectorMtlsFilter) valida que cert CN==tenant_id e OU==collector_id.
// Zero secrets adicionais no agente.
package configpull

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Applier é a interface mínima exposta pelo scheduler pra receber deltas.
// Implementada por *checks.Runtime via ApplyDelta — desacoplado de proto.
type Applier interface {
	ApplyDelta(added []*collectorv1.CheckConfig, deletedIDs []string) (int, int)
}

// Config controla o cliente.
type Config struct {
	Endpoint     string        // base URL do servidor (ex: https://quarkus:8444)
	CollectorID  string        // UUID do collector (vai como query param + cert OU)
	TenantID     string        // pra logging + query param + cert CN
	PollInterval time.Duration // entre pulls (default 10s)

	// Phase 5b — material mTLS. Quando ClientCert/ClientKey estão setados e
	// HTTPClient é nil, o pacote constrói um *http.Client com tls.Config
	// carregando cert + key + trust bundle. TrustBundle vazio = system roots.
	ClientCert  string
	ClientKey   string
	TrustBundle string

	HTTPClient *http.Client // se setado, é usado direto (testes injetam mock)
	Logger     *slog.Logger
}

// Run inicia o loop em foreground (bloqueante). Chamar em goroutine.
// Encerra quando ctx é cancelado.
func Run(ctx context.Context, cfg Config, applier Applier) error {
	if cfg.Endpoint == "" {
		return fmt.Errorf("configpull: empty endpoint")
	}
	if cfg.CollectorID == "" {
		return fmt.Errorf("configpull: empty collector_id")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "configpull")

	client := cfg.HTTPClient
	if client == nil {
		c, err := buildMTLSClient(cfg)
		if err != nil {
			return fmt.Errorf("configpull: build mTLS client: %w", err)
		}
		client = c
	}

	var sinceVer atomic.Int64
	log.Info("config pull loop starting",
		"endpoint", cfg.Endpoint, "collector_id", cfg.CollectorID,
		"poll_interval", cfg.PollInterval.String())

	// 1) Pull imediato pra warm-up
	if err := pullOnce(ctx, client, cfg, &sinceVer, applier, log); err != nil {
		log.Warn("config pull initial failed (continuing)", "err", err)
	}
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("config pull loop stopping")
			return nil
		case <-ticker.C:
			if err := pullOnce(ctx, client, cfg, &sinceVer, applier, log); err != nil {
				log.Warn("config pull failed", "err", err)
				// Continua: próximo tick tenta de novo. Nenhum backoff exponencial
				// porque pollInterval já é razoável e a ideia é ser previsível.
			}
		}
	}
}

type pullResponse struct {
	Version        int64           `json:"version"`
	AddedOrUpdated []pulledCheck   `json:"added_or_updated"`
	DeletedIds     []string        `json:"deleted_ids"`
}

type pulledCheck struct {
	ID              string `json:"id"`
	CheckType       string `json:"check_type"`
	HostId          int64  `json:"host_id"`
	Hostname        string `json:"hostname"`
	ExternalId      string `json:"external_id"`
	Params          string `json:"params"`        // JSON string
	StaticTags      string `json:"static_tags"`   // JSON string
	IntervalSeconds int32  `json:"interval_seconds"`
	ConfigVersion   int64  `json:"config_version"`
	DisabledMetrics string `json:"disabled_metrics"` // JSON array of metric names, e.g. ["snmp_if_in_octets"]
}

func pullOnce(
	ctx context.Context,
	client *http.Client,
	cfg Config,
	sinceVer *atomic.Int64,
	applier Applier,
	log *slog.Logger,
) error {
	since := sinceVer.Load()
	u := fmt.Sprintf("%s/api/collector/v1/config?tenant_id=%s&collector_id=%s&since=%d",
		cfg.Endpoint,
		url.QueryEscape(cfg.TenantID),
		url.QueryEscape(cfg.CollectorID),
		since)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil { return err }
	req.Header.Set("Accept", "application/json")

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var r pullResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Curto-circuito: nada mudou
	if r.Version == since && len(r.AddedOrUpdated) == 0 && len(r.DeletedIds) == 0 {
		log.Debug("config pull: no change", "version", since, "took_ms", time.Since(t0).Milliseconds())
		return nil
	}

	// Converte pra CheckConfig protos e aplica delta no scheduler.
	cfgs := make([]*collectorv1.CheckConfig, 0, len(r.AddedOrUpdated))
	for _, p := range r.AddedOrUpdated {
		cb := collectorv1.CheckConfig{
			CheckId:    p.ID,
			CheckType:  p.CheckType,
			HostId:     fmt.Sprintf("%d", p.HostId),
			Enabled:    true,
			Interval:   nil, // setado abaixo
		}
		// Interval em segundos → durationpb.Duration
		if p.IntervalSeconds > 0 {
			cb.Interval = durationpb.New(time.Duration(p.IntervalSeconds) * time.Second)
		}
		// params + static_tags JSONB → map<string,string>
		cb.Params = jsonObjectToStringMap(p.Params)
		cb.StaticTags = jsonObjectToStringMap(p.StaticTags)
		// Injeta target pros checks remotos (snmp.*, icmp.*) — preferindo
		// external_id (IP real) sobre hostname. Esse fallback também existia
		// no path legado (CollectorServiceImpl.loadChecksFromDb).
		if (startsWith(p.CheckType, "snmp.") || startsWith(p.CheckType, "icmp.")) && cb.Params != nil {
			if _, has := cb.Params["target"]; !has {
				target := p.ExternalId
				if target == "" { target = p.Hostname }
				if target != "" { cb.Params["target"] = target }
			}
		}
		// Injeta disabled_metrics no params pra que o check SNMP filtre
		// métricas desabilitadas pelo usuário. Valor é JSON array string.
		if p.DisabledMetrics != "" && p.DisabledMetrics != "[]" {
			if cb.Params == nil { cb.Params = make(map[string]string) }
			cb.Params["disabled_metrics"] = p.DisabledMetrics
		}
		cfgs = append(cfgs, &cb)
	}

	added, removed := applier.ApplyDelta(cfgs, r.DeletedIds)
	sinceVer.Store(r.Version)
	log.Info("config pull: delta applied",
		"from_version", since, "to_version", r.Version,
		"added", added, "removed", removed,
		"took_ms", time.Since(t0).Milliseconds())
	return nil
}

func jsonObjectToStringMap(s string) map[string]string {
	if s == "" || s == "{}" { return map[string]string{} }
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case string: out[k] = t
		case float64: out[k] = fmt.Sprintf("%v", t)
		case bool: out[k] = fmt.Sprintf("%v", t)
		default: out[k] = fmt.Sprintf("%v", t)
		}
	}
	return out
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func min(a, b int) int { if a < b { return a }; return b }

// buildMTLSClient monta um *http.Client com client cert + trust bundle.
//
// Em dev, se ClientCert ou ClientKey estão vazios, devolve um client com
// InsecureSkipVerify=true (mantém a UX antiga pra `go run` sem PKI). Em
// produção, o caller sempre passa os 3 paths e o handshake falha loud se
// algum arquivo é inválido.
func buildMTLSClient(cfg Config) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		pair, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert (%s, %s): %w", cfg.ClientCert, cfg.ClientKey, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else {
		// Dev/test fallback — sem cert o agent não consegue passar pelo
		// CollectorMtlsFilter, mas o skip-verify mantém o handshake até o
		// 403, facilitando debug "esqueci o cert" vs. "cert errado".
		tlsCfg.InsecureSkipVerify = true
	}

	if cfg.TrustBundle != "" {
		pem, err := os.ReadFile(cfg.TrustBundle)
		if err != nil {
			return nil, fmt.Errorf("read trust bundle %s: %w", cfg.TrustBundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust bundle %s contained no PEM certs", cfg.TrustBundle)
		}
		tlsCfg.RootCAs = pool
	} else if !tlsCfg.InsecureSkipVerify {
		// Sem trust bundle explícito, usa system roots (que em geral não
		// confiam na PKI interna do collector). Mantém o flag InsecureSkipVerify
		// apagado pra falhar loud se o operador esqueceu de passar.
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}
