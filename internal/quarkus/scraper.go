// Package quarkus implementa o scrape periódico do endpoint /q/metrics
// (Micrometer/Prometheus exposition) de pods marcados pela UI como
// instrumented mode=quarkus_metrics.
//
// Decisões locked:
//
//   - Lista de pods vem do nosso backend (/api/collector/v1/k8s/instrumentation),
//     NÃO do manifest do cliente. Cliente nunca anota nada no pod.
//
//   - Resolução de pod IP via kubelet local (/pods) — só pods rodando neste
//     nó são scrapeados por este agent. Naturalmente distribui o trabalho
//     entre os DaemonSet agents: 1 agent por nó scrape os pods locais.
//
//   - Parser Prometheus minimalista: aceita gauges + counters simples,
//     ignora histograms/summaries (têm shape complexo). Foco no que
//     Micrometer + Quarkus expõem por default (JVM heap, GC, HTTP rate).
//
//   - Best-effort: pod ausente, scrape 404, parse erro — log debug e
//     próximo ciclo. Não queremos derrubar nada.

package quarkus

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultInterval       = 30 * time.Second
	defaultScrapePath     = "/q/metrics"
	defaultScrapePort     = 8080
	defaultKubeletURL     = "https://localhost:10250"
	defaultKubeletTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubeletCAFile  = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	scrapeTimeout         = 5 * time.Second
)

// Scraper roda um loop polling no backend pra descobrir quais pods
// instrumentar e scrape /q/metrics de cada um.
type Scraper struct {
	backend      string // ex: https://quarkus:8444
	tenantID     string
	collectorID  string
	clientCert   string
	clientKey    string
	trustBundle  string
	out          chan<- []*collectorv1.Metric
	log          *slog.Logger
	interval     time.Duration
}

func New(backend, tenantID, collectorID string,
	clientCert, clientKey, trustBundle string,
	out chan<- []*collectorv1.Metric,
	log *slog.Logger) *Scraper {
	return &Scraper{
		backend:     backend,
		tenantID:    tenantID,
		collectorID: collectorID,
		clientCert:  clientCert,
		clientKey:   clientKey,
		trustBundle: trustBundle,
		out:         out,
		log:         log.With("component", "quarkus-scraper"),
		interval:    defaultInterval,
	}
}

func (s *Scraper) Run(ctx context.Context) {
	s.log.Info("quarkus scraper started", "backend", s.backend, "interval", s.interval)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	// Tick imediato pra não ter delay de 30s no primeiro scrape.
	s.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
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

func (s *Scraper) tick(ctx context.Context) {
	list, err := s.fetchList(ctx)
	if err != nil {
		s.log.Warn("instrumentation fetch failed", "err", err)
		return
	}
	if len(list) == 0 {
		return
	}
	// Cache de pods locais pra reusar na iteração.
	podIPs, podErr := s.localPodIPs(ctx)
	if podErr != nil {
		s.log.Warn("local pod list failed", "err", podErr)
		return
	}
	scraped := 0
	for _, e := range list {
		if e.Mode != "quarkus_metrics" {
			continue
		}
		ip, ok := podIPs[podKey(e.Namespace, e.Pod)]
		if !ok || ip == "" {
			continue // pod não está neste nó — outro agent cuida
		}
		metrics, err := s.scrapePod(ctx, ip, e.Namespace, e.Pod)
		if err != nil {
			s.log.Warn("scrape failed", "ns", e.Namespace, "pod", e.Pod, "ip", ip, "err", err)
			continue
		}
		if len(metrics) > 0 {
			select {
			case s.out <- metrics:
				scraped++
				s.log.Info("quarkus metrics scraped", "pod", e.Pod, "count", len(metrics))
			default:
				s.log.Warn("metric out channel full, dropped batch", "pod", e.Pod)
			}
		}
	}
	if scraped == 0 && len(list) > 0 {
		s.log.Info("quarkus scraper tick: no pods on this node matched", "list_size", len(list))
	}
}

// fetchList GET backend /api/collector/v1/k8s/instrumentation?tenant_id=X
// usando mTLS já configurado (mesmo cert dos outros caminhos REST).
func (s *Scraper) fetchList(ctx context.Context) ([]instrEntry, error) {
	url := strings.TrimRight(s.backend, "/") +
		"/api/collector/v1/k8s/instrumentation?tenant_id=" + s.tenantID +
		"&collector_id=" + s.collectorID
	client, err := s.mtlsClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	var r instrResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Entries, nil
}

func (s *Scraper) mtlsClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(s.clientCert, s.clientKey)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	pool := x509.NewCertPool()
	caBytes, err := os.ReadFile(s.trustBundle)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("CA bundle empty")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			},
		},
	}, nil
}

// localPodIPs lê /pods do kubelet local — devolve {ns/pod → ip} apenas
// pra pods rodando neste nó. Pod IP é tirado de status.podIP.
type kubeletPodList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			PodIP string `json:"podIP"`
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

func (s *Scraper) localPodIPs(ctx context.Context) (map[string]string, error) {
	client, err := newKubeletClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultKubeletURL+"/pods", nil)
	if err != nil {
		return nil, err
	}
	if tok := readBearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("kubelet /pods status %d", resp.StatusCode)
	}
	var list kubeletPodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(list.Items))
	for _, p := range list.Items {
		if p.Status.PodIP == "" || p.Status.Phase != "Running" {
			continue
		}
		out[podKey(p.Metadata.Namespace, p.Metadata.Name)] = p.Status.PodIP
	}
	return out, nil
}

func podKey(ns, pod string) string {
	return ns + "/" + pod
}

func newKubeletClient() (*http.Client, error) {
	tlsCfg := &tls.Config{}
	if caBytes, err := os.ReadFile(defaultKubeletCAFile); err == nil && len(caBytes) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBytes) {
			tlsCfg.RootCAs = pool
		}
	}
	if tlsCfg.RootCAs == nil {
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   scrapeTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func readBearerToken() string {
	b, err := os.ReadFile(defaultKubeletTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// scrapePod faz GET http://podIP:8080/q/metrics e parseia o formato
// Prometheus exposition. Retorna []*Metric com tag namespace/pod.
func (s *Scraper) scrapePod(ctx context.Context, podIP, namespace, pod string) ([]*collectorv1.Metric, error) {
	url := fmt.Sprintf("http://%s:%d%s", podIP, defaultScrapePort, defaultScrapePath)
	client := &http.Client{Timeout: scrapeTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("scrape status %d", resp.StatusCode)
	}
	return parsePrometheus(resp.Body, namespace, pod), nil
}

// parsePrometheus suporta o subset que Micrometer + Quarkus expõem:
//   - linhas '# TYPE name kind' (gauge/counter); histogram/summary
//     são tratados como gauges das séries individuais (já têm sufixo
//     _bucket/_count/_sum no nome).
//   - "metric_name{label="value",...} 1.234" pra series com labels.
//   - "metric_name 1.234" pra series sem labels.
//   - Comentários (#) ignorados (exceto # TYPE).
//
// Não filtramos por allowlist aqui — o backend (VmRemoteWriter) já tem
// regex que aceita "qualquer letra inicial". Vamos prefixar com 'quarkus_'
// pra deixar claro no VM browser que vem dessa origem.
func parsePrometheus(r io.Reader, namespace, pod string) []*collectorv1.Metric {
	out := []*collectorv1.Metric{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	now := timestamppb.Now()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, value, ok := parseLine(line)
		if !ok {
			continue
		}
		tags := map[string]string{"namespace": namespace, "pod": pod}
		for k, v := range labels {
			tags[k] = v
		}
		out = append(out, &collectorv1.Metric{
			Time:       now,
			HostId:     "",
			MetricName: "quarkus." + name,
			Value:      value,
			Tags:       tags,
			Source:     "quarkus.metrics",
		})
	}
	return out
}

// parseLine: "name{k="v",k2="v2"} 1.234" → name, {k:v, k2:v2}, 1.234.
// Suporta variant sem labels: "name 1.234".
func parseLine(line string) (name string, labels map[string]string, value float64, ok bool) {
	// Split em (name+labels) e value pela última whitespace.
	spaceIdx := strings.LastIndexAny(line, " \t")
	if spaceIdx < 0 {
		return "", nil, 0, false
	}
	head := line[:spaceIdx]
	val := strings.TrimSpace(line[spaceIdx+1:])
	v, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return "", nil, 0, false
	}
	labels = map[string]string{}
	braceIdx := strings.IndexByte(head, '{')
	if braceIdx < 0 {
		return strings.TrimSpace(head), labels, v, true
	}
	name = head[:braceIdx]
	rest := head[braceIdx+1:]
	endBrace := strings.LastIndexByte(rest, '}')
	if endBrace < 0 {
		return "", nil, 0, false
	}
	labelStr := rest[:endBrace]
	// Parse k="v",k2="v2" — assumindo formato canônico do Prometheus.
	// Escape " dentro de valores não é comum em Micrometer; ignoramos.
	for _, pair := range splitLabelPairs(labelStr) {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(pair[:eq])
		v := strings.TrimSpace(pair[eq+1:])
		v = strings.Trim(v, "\"")
		if k != "" {
			labels[k] = v
		}
	}
	return strings.TrimSpace(name), labels, v, true
}

// splitLabelPairs respeita aspas — não usa split simples por vírgula
// porque valores podem conter vírgula.
func splitLabelPairs(s string) []string {
	parts := []string{}
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
			continue
		}
		if c == ',' && !inQuotes {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
