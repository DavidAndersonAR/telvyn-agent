// http_throughput.go — Check "http.throughput" para link_probe.
//
// Faz download de uma URL conhecida (ex: speed.cloudflare.com com size
// fixo, ou um asset grande hospedado pelo proprio cliente) e mede a
// taxa efetiva de transferencia. Util para detectar "lentidao" de
// uplink onde ping/latencia parecem OK mas throughput cai.
//
// Limita o tempo total a timeout_ms para nao queimar dados nem deixar
// goroutine pendurada quando o link engasga no meio.
//
// Metricas:
//   http.throughput_mbps      - megabits/segundo medido
//   http.throughput_bytes     - bytes baixados no ciclo
//   http.throughput_ms        - duracao da transferencia
//   http.throughput_success   - 0/1
//
// Params:
//   target                  - URL com payload de download
//   max_bytes               - opcional, default 10485760 (10 MB); 0 = sem limite
//   source_iface/source_ip  - source binding
//   timeout_ms              - default 15000

package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type httpThroughputCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	target      string
	maxBytes    int64
	timeout     time.Duration
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

func newHTTPThroughputCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("http.throughput: missing param 'target'")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return nil, fmt.Errorf("http.throughput: target must begin with http:// or https://")
	}

	maxBytes := int64(parseIntParam(params, "max_bytes", 10*1024*1024))
	if maxBytes < 0 {
		maxBytes = 0
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		// Throughput probes sao caras — default conservador, 5min.
		interval = 5 * time.Minute
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "http.throughput-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &httpThroughputCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		target:      target,
		maxBytes:    maxBytes,
		timeout:     parseTimeoutMs(params, 15000),
		sourceIface: params["source_iface"],
		sourceIP:    params["source_ip"],
		staticTags:  tags,
	}, nil
}

func (c *httpThroughputCheck) ID() string              { return c.id }
func (c *httpThroughputCheck) Interval() time.Duration { return c.interval }
func (c *httpThroughputCheck) Tags() map[string]string { return c.staticTags }

func (c *httpThroughputCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	dialer := newBindingDialer(c.sourceIface, c.sourceIP, c.timeout)
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: c.timeout,
		TLSHandshakeTimeout:   c.timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", c.target, nil)
	if err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "http.throughput_success", 0)}, nil
	}
	req.Header.Set("User-Agent", "ispwatch-collector/link-probe")
	req.Header.Set("Accept-Encoding", "identity") // sem compressao: medir bytes do fio

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "http.throughput_success", 0)}, nil
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if c.maxBytes > 0 {
		reader = io.LimitReader(resp.Body, c.maxBytes)
	}
	n, _ := io.Copy(io.Discard, reader)
	elapsed := time.Since(start)

	now := timestamppb.Now()
	var mbps float64
	if elapsed > 0 && n > 0 {
		mbps = (float64(n) * 8) / 1_000_000 / elapsed.Seconds()
	}
	success := 0.0
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && n > 0 {
		success = 1
	}
	return []*collectorv1.Metric{
		c.metric(now, "http.throughput_mbps", mbps),
		c.metric(now, "http.throughput_bytes", float64(n)),
		c.metric(now, "http.throughput_ms", float64(elapsed)/float64(time.Millisecond)),
		c.metric(now, "http.throughput_success", success),
	}, nil
}

func (c *httpThroughputCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+1)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["target"] = c.target
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "http",
	}
}

func init() {
	Default.Register("http.throughput", newHTTPThroughputCheck)
}
