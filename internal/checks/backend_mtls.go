// backend_mtls.go — utilitário pra checks postarem dados de volta no
// servidor central usando o mesmo cert mTLS já carregado pelo agent.
//
// Sem refactor agressivo: o main.go injeta a config aqui (cert/key/trust +
// endpoint + tenant + collector) uma vez no boot. Checks que precisam
// chamar o backend (ex: zabbix.sync postando lotes de hosts) consomem via
// PostJSON. Não há leitura concorrente do alvo durante runtime — config
// é write-once.
package checks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type backendConfig struct {
	httpClient  *http.Client
	endpoint    string // ex: https://quarkus:8444
	tenantID    string
	collectorID string
}

var backendCfg atomic.Pointer[backendConfig]

// SetBackend é chamada uma vez pelo main.go com os mesmos paths de cert que
// o configpull usa. Se algum dos paths é vazio, monta um client com
// InsecureSkipVerify — o handshake vai falhar no servidor mas pelo menos
// o erro é claro ("cert/query identity mismatch" do filter).
func SetBackend(endpoint, tenantID, collectorID, certPath, keyPath, trustPath string) error {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" && keyPath != "" {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("load client cert (%s, %s): %w", certPath, keyPath, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	if trustPath != "" {
		pem, err := os.ReadFile(trustPath)
		if err != nil {
			return fmt.Errorf("read trust bundle %s: %w", trustPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("trust bundle %s contained no PEM certs", trustPath)
		}
		tlsCfg.RootCAs = pool
	}
	cli := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}
	backendCfg.Store(&backendConfig{
		httpClient:  cli,
		endpoint:    strings.TrimRight(endpoint, "/"),
		tenantID:    tenantID,
		collectorID: collectorID,
	})
	return nil
}

// PostJSON envia body como application/json para endpoint+path, injetando
// tenant_id+collector_id como query params (o CollectorMtlsFilter requer).
// Retorna o body da resposta (até maxResponseBytes) ou erro.
func PostJSON(ctx context.Context, path string, body any) ([]byte, error) {
	return PostJSONOrGet(ctx, "POST", path, body)
}

// PostJSONOrGet permite escolher o método HTTP; mantém auth + query
// injection consistente entre todas chamadas mTLS do agent.
func PostJSONOrGet(ctx context.Context, method, path string, body any) ([]byte, error) {
	cfg := backendCfg.Load()
	if cfg == nil {
		return nil, fmt.Errorf("backend mTLS not configured (SetBackend was not called)")
	}

	var bodyReader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	u, err := url.Parse(cfg.endpoint + path)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	q.Set("tenant_id", cfg.tenantID)
	q.Set("collector_id", cfg.collectorID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("backend %d: %s", resp.StatusCode, truncateString(string(respBody), 200))
	}
	return respBody, nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
