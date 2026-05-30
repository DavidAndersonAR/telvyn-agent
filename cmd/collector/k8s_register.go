// k8s_register.go — boot-time call into the central server to register
// this node as a noc_host + provision the k8s.kubelet check.
//
// Only fires when NODE_NAME env is present (set by Helm DaemonSet via
// downward API). Outside of k8s the call is a no-op so binary stays
// portable for bare-metal and docker-compose installs.

package main

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
	"time"
)

type k8sRegisterPayload struct {
	NodeName    string `json:"node_name"`
	ClusterName string `json:"cluster_name"`
	NodeIP      string `json:"node_ip,omitempty"`
	K8sVersion  string `json:"k8s_version,omitempty"`
}

type k8sRegisterResp struct {
	HostID   int64  `json:"host_id"`
	HostUUID string `json:"host_uuid"`
	CheckID  string `json:"check_id"`
	Hostname string `json:"hostname"`
}

// autoRegisterK8sIfNeeded checks for NODE_NAME env and, if present,
// calls /api/noc/hosts/auto-register on the central server via mTLS.
//
// Failure is logged but non-fatal — the agent still attempts to run
// (it just won't have a k8s.kubelet check assigned until manual
// registration happens). This matches the "best effort boot" pattern
// used by other agent integrations.
func autoRegisterK8sIfNeeded(
	ctx context.Context,
	log *slog.Logger,
	httpEndpoint, clientCert, clientKey, trustBundle string,
) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return
	}
	cluster := os.Getenv("ISPWATCH_CLUSTER")
	if cluster == "" {
		cluster = "default"
	}
	nodeIP := os.Getenv("NODE_IP")
	k8sVersion := os.Getenv("K8S_VERSION") // optional, may be empty

	payload := k8sRegisterPayload{
		NodeName:    nodeName,
		ClusterName: cluster,
		NodeIP:      nodeIP,
		K8sVersion:  k8sVersion,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Warn("k8s auto-register marshal failed", "err", err)
		return
	}

	client, err := buildK8sRegisterClient(clientCert, clientKey, trustBundle)
	if err != nil {
		log.Warn("k8s auto-register: TLS setup failed", "err", err)
		return
	}

	// Endpoint vive sob /api/collector/v1/ pra herdar o CollectorMtlsFilter
	// — exige query params tenant_id+collector_id que batem com CN/OU do cert
	// (validação dupla além do TLS handshake).
	tenantID := os.Getenv("COLLECTOR_TENANT_ID")
	collectorID := os.Getenv("COLLECTOR_ID")
	if tenantID == "" || collectorID == "" {
		log.Warn("k8s auto-register skipped: COLLECTOR_TENANT_ID/COLLECTOR_ID not set",
			"tenant", tenantID, "collector", collectorID)
		return
	}
	url := strings.TrimRight(httpEndpoint, "/") +
		"/api/collector/v1/k8s/auto-register" +
		"?tenant_id=" + tenantID +
		"&collector_id=" + collectorID

	// Retry com backoff curto pra absorver race com Quarkus em startup.
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			cancel()
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode/100 == 2 {
			var parsed k8sRegisterResp
			_ = json.Unmarshal(respBody, &parsed)
			log.Info("k8s auto-register OK",
				"node", nodeName, "cluster", cluster,
				"host_id", parsed.HostID, "host_uuid", parsed.HostUUID,
				"check_id", parsed.CheckID)
			return
		}
		lastErr = fmt.Errorf("status %d body=%s", resp.StatusCode, respBody)
		// 4xx é client error — não retentar
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			break
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	log.Warn("k8s auto-register failed (continuing)", "err", lastErr,
		"node", nodeName, "cluster", cluster)
}

func buildK8sRegisterClient(clientCert, clientKey, trustBundle string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if clientCert != "" && clientKey != "" {
		pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	if trustBundle != "" {
		pem, err := os.ReadFile(trustBundle)
		if err != nil {
			return nil, fmt.Errorf("read trust bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust bundle has no PEM certs")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
