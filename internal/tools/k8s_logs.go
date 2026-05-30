// k8s_logs.go — Tool "k8s.logs". Proxy de logs do kubelet local.
//
// Quarkus não alcança o kubelet (vive fora do cluster). O agent que roda como
// DaemonSet pode falar com localhost:10250/containerLogs. Esta tool é
// chamada via reverse ToolChannel (gRPC) quando o UI/operador pede logs
// de um pod específico.
//
// Args:
//
//	namespace   string   required
//	pod         string   required
//	container   string   required — kubelet exige container name no path
//	tail_lines  number   optional  default 200, max 5000
//	since_seconds number optional  janela máxima
//	timestamps  bool     optional  default true — kubelet prepend RFC3339
//	previous    bool     optional  default false — logs do container anterior
//	                                (útil pra debug de crash)
//
// Returns:
//
//	result["lines"]  []string  uma string por linha do log
//	result["count"]  number    len(lines)
//	result["truncated"] bool   true se kubelet retornou exatamente tail_lines
//
// Auth: mesmo bearer token + CA do check k8s.kubelet (SA mount).

package tools

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	k8sLogsDefaultKubeletURL = "https://localhost:10250"
	k8sLogsDefaultTokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sLogsDefaultCAFile     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sLogsDefaultTail       = 200
	k8sLogsMaxTail           = 5000
	k8sLogsTimeout           = 15 * time.Second
)

// K8sLogs implements tools.Executor pra "k8s.logs".
type K8sLogs struct{}

func (K8sLogs) Name() string { return "k8s.logs" }

func (K8sLogs) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	ns := strings.TrimSpace(asString(args["namespace"]))
	pod := strings.TrimSpace(asString(args["pod"]))
	container := strings.TrimSpace(asString(args["container"]))
	if ns == "" || pod == "" || container == "" {
		return nil, fmt.Errorf("k8s.logs requires namespace, pod, container")
	}
	if !isSafeK8sName(ns) || !isSafeK8sName(pod) || !isSafeK8sName(container) {
		return nil, fmt.Errorf("k8s.logs args contain invalid characters")
	}

	tail := asInt(args["tail_lines"], k8sLogsDefaultTail)
	if tail <= 0 {
		tail = k8sLogsDefaultTail
	}
	if tail > k8sLogsMaxTail {
		tail = k8sLogsMaxTail
	}
	since := asInt(args["since_seconds"], 0)
	timestamps := asBool(args["timestamps"], true)
	previous := asBool(args["previous"], false)

	kubeletURL := strings.TrimSpace(asString(args["kubelet_url"]))
	if kubeletURL == "" {
		kubeletURL = k8sLogsDefaultKubeletURL
	}

	q := url.Values{}
	q.Set("tailLines", strconv.Itoa(tail))
	if since > 0 {
		q.Set("sinceSeconds", strconv.Itoa(since))
	}
	if timestamps {
		q.Set("timestamps", "true")
	}
	if previous {
		q.Set("previous", "true")
	}

	fullURL := strings.TrimRight(kubeletURL, "/") +
		"/containerLogs/" + url.PathEscape(ns) +
		"/" + url.PathEscape(pod) +
		"/" + url.PathEscape(container) +
		"?" + q.Encode()

	client, err := newKubeletClient()
	if err != nil {
		return nil, fmt.Errorf("k8s.logs: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, k8sLogsTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("k8s.logs new req: %w", err)
	}
	if tok := readBearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s.logs GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("k8s.logs status %d body=%q", resp.StatusCode, body)
	}

	// kubelet devolve text/plain, 1 linha por log entry (com timestamps quando
	// pedido). Streaming raw: lemos linha-a-linha pra não estourar memória se
	// alguém pedir tail=5000 num app verboso.
	lines := make([]string, 0, tail)
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 16*1024*1024)) // hard cap 16MiB
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)                  // até 1MiB por linha
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	// Não propagar erros de scanner pra cima — se truncou no meio, devolve o
	// que tem. UI já indica que vem do kubelet.

	return map[string]any{
		"lines":     anyStrings(lines),
		"count":     len(lines),
		"truncated": len(lines) >= tail,
	}, nil
}

// ── helpers ─────────────────────────────────────────────────────────────

func newKubeletClient() (*http.Client, error) {
	tlsCfg := &tls.Config{}
	if caBytes, err := os.ReadFile(k8sLogsDefaultCAFile); err == nil && len(caBytes) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBytes) {
			tlsCfg.RootCAs = pool
		}
	}
	if tlsCfg.RootCAs == nil {
		// Kubelet local quase sempre tem cert self-signed; agente vive na mesma
		// máquina, então SkipVerify é aceitável (mesma decisão do check
		// k8s.kubelet).
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   k8sLogsTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func readBearerToken() string {
	b, err := os.ReadFile(k8sLogsDefaultTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// k8s names: lowercase RFC-1123 + dots. Rejeita injection no path.
func isSafeK8sName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return true
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func asInt(v any, def int) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return def
}
func asBool(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		if x == "true" || x == "1" {
			return true
		}
		if x == "false" || x == "0" {
			return false
		}
	}
	return def
}
func anyStrings(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
