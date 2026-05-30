// enroll.go — bootstrap enrollment: trades an install-time token for a
// long-lived client cert minted by the central server.
//
// Triggered on first boot when:
//   - env ISPWATCH_BOOTSTRAP_TOKEN is set (and non-empty), AND
//   - cert file (env ISPWATCH_CERT_FILE, default $WAL_DIR/pki/client.cert.pem)
//     does NOT exist yet.
//
// On subsequent boots the cert file is present, this path is a no-op, and the
// agent comes up directly on its individual identity. Matches the "1 agent =
// 1 host" model: each pod / VM / container gets its own cert tied to its
// hostname/node identity. DaemonSet works because the bootstrap token is
// multi-use server-side.
//
// Output written to disk:
//   $WAL_DIR/pki/client.cert.pem    (cert chain)
//   $WAL_DIR/pki/client.key.pem     (private key, mode 0600)
//   $WAL_DIR/pki/ca.crt             (trust bundle)
//   $WAL_DIR/pki/identity.env       (tenant_id, collector_id, grpc_endpoint)
//
// identity.env is sourced by entrypoint.sh to populate COLLECTOR_TENANT_ID /
// COLLECTOR_ID / COLLECTOR_SERVER for the main process.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type enrollRequest struct {
	AgentKind  string `json:"agent_kind"`
	NodeName   string `json:"node_name"`
	Cluster    string `json:"cluster,omitempty"`
	NodeIP     string `json:"node_ip,omitempty"`
	K8sVersion string `json:"k8s_version,omitempty"`
}

type enrollResponse struct {
	CollectorID string `json:"collector_id"`
	TenantID    string `json:"tenant_id"`
	Server      struct {
		GrpcEndpoint string `json:"grpc_endpoint"`
	} `json:"server"`
	Pki struct {
		CertPem         string `json:"cert_pem"`
		KeyPem          string `json:"key_pem"`
		IntermediatePem string `json:"intermediate_pem"`
		RootPem         string `json:"root_pem"`
	} `json:"pki"`
}

// enrollIfNeeded runs the bootstrap flow if ISPWATCH_BOOTSTRAP_TOKEN is set
// and no cert exists yet. Returns nil if enrollment ran successfully OR if
// it was not needed. Returns error only if enrollment was attempted and
// failed (caller exits 1 — pod will restart and retry).
func enrollIfNeeded(ctx context.Context, log *slog.Logger) error {
	token := strings.TrimSpace(os.Getenv("ISPWATCH_BOOTSTRAP_TOKEN"))
	if token == "" {
		return nil // not in bootstrap mode
	}

	pkiDir := os.Getenv("ISPWATCH_PKI_DIR")
	if pkiDir == "" {
		// Default colocated with WAL; both are emptyDir in k8s pods.
		walPath := os.Getenv("ISPWATCH_WAL_PATH")
		if walPath == "" {
			walPath = "/var/lib/ispwatch-collector/wal.db"
		}
		pkiDir = filepath.Join(filepath.Dir(walPath), "pki")
	}

	certPath := filepath.Join(pkiDir, "client.cert.pem")
	if _, err := os.Stat(certPath); err == nil {
		log.Info("enrollment: cert already present, skipping", "path", certPath)
		return nil
	}

	enrollURL := strings.TrimSpace(os.Getenv("ISPWATCH_ENROLL_URL"))
	if enrollURL == "" {
		return errors.New("ISPWATCH_BOOTSTRAP_TOKEN set but ISPWATCH_ENROLL_URL missing")
	}

	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		// Fallback for non-k8s installs.
		host, _ := os.Hostname()
		nodeName = host
	}
	if nodeName == "" {
		return errors.New("could not determine node_name (NODE_NAME unset and os.Hostname failed)")
	}

	agentKind := os.Getenv("ISPWATCH_AGENT_KIND")
	if agentKind == "" {
		if os.Getenv("ISPWATCH_CLUSTER") != "" {
			agentKind = "k8s.node"
		} else {
			agentKind = "linux.host"
		}
	}

	payload := enrollRequest{
		AgentKind:  agentKind,
		NodeName:   nodeName,
		Cluster:    os.Getenv("ISPWATCH_CLUSTER"),
		NodeIP:     os.Getenv("NODE_IP"),
		K8sVersion: os.Getenv("K8S_VERSION"),
	}

	log.Info("enrollment: starting",
		"url", enrollURL, "agent_kind", agentKind, "node", nodeName,
		"cluster", payload.Cluster)

	resp, err := postEnroll(ctx, enrollURL, token, payload)
	if err != nil {
		return fmt.Errorf("enrollment POST: %w", err)
	}

	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", pkiDir, err)
	}
	if err := writeFile(certPath, resp.Pki.CertPem+resp.Pki.IntermediatePem, 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(pkiDir, "client.key.pem"), resp.Pki.KeyPem, 0600); err != nil {
		return err
	}
	// Trust bundle: intermediate + root (server is signed under same intermediate).
	trustPem := resp.Pki.IntermediatePem
	if resp.Pki.RootPem != "" {
		trustPem += resp.Pki.RootPem
	}
	if err := writeFile(filepath.Join(pkiDir, "ca.crt"), trustPem, 0644); err != nil {
		return err
	}

	// identity.env consumed by entrypoint.sh — usa `export` pra que as vars
	// propaguem pro Go binary via env (autoRegisterK8sIfNeeded usa os.Getenv).
	identity := fmt.Sprintf(
		"export COLLECTOR_TENANT_ID=%s\nexport COLLECTOR_ID=%s\nexport COLLECTOR_SERVER=%s\n",
		resp.TenantID, resp.CollectorID, resp.Server.GrpcEndpoint,
	)
	if err := writeFile(filepath.Join(pkiDir, "identity.env"), identity, 0644); err != nil {
		return err
	}

	log.Info("enrollment: success",
		"tenant", resp.TenantID,
		"collector_id", resp.CollectorID,
		"grpc_endpoint", resp.Server.GrpcEndpoint,
		"pki_dir", pkiDir)
	return nil
}

func postEnroll(ctx context.Context, url, token string, body enrollRequest) (*enrollResponse, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	// Use the trust bundle if provided (production) — accept any cert otherwise
	// (dev with self-signed servers). The bootstrap token is the authentication;
	// TLS here is just for transport encryption.
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if trustFile := os.Getenv("ISPWATCH_ENROLL_TRUST_BUNDLE"); trustFile != "" {
		pem, err := os.ReadFile(trustFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = pool
			}
		}
	} else if os.Getenv("ISPWATCH_ENROLL_INSECURE_TLS") == "1" {
		tlsCfg.InsecureSkipVerify = true
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// Retry com backoff curto pra absorver race com Quarkus em startup.
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(buf))
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		// Custom header em vez de Authorization: Bearer — JWT mechanism do
		// servidor intercepta Authorization antes do endpoint @PermitAll.
		req.Header.Set("X-Bootstrap-Token", token)

		resp, err := httpClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			var er enrollResponse
			if err := json.Unmarshal(bodyBytes, &er); err != nil {
				return nil, fmt.Errorf("decode response: %w (body=%s)", err, string(bodyBytes))
			}
			if er.Pki.CertPem == "" || er.Pki.KeyPem == "" {
				return nil, fmt.Errorf("server response missing cert/key (body=%s)", string(bodyBytes))
			}
			return &er, nil
		}
		// 4xx é client error — não retentar (token revogado, expirado, etc).
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("enrollment refused: status=%d body=%s", resp.StatusCode, string(bodyBytes))
		}
		lastErr = fmt.Errorf("status=%d body=%s", resp.StatusCode, string(bodyBytes))
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	return nil, fmt.Errorf("enrollment exhausted retries: %w", lastErr)
}

func writeFile(path, content string, mode os.FileMode) error {
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
