// nginx_server.go — Check "nginx.server" implementação contínua.
//
// Coleta métricas do nginx via módulo stub_status (configurado no nginx
// com `location /nginx_status { stub_status; allow 127.0.0.1; deny all; }`).
// Output canônico do stub_status:
//
//   Active connections: 291
//   server accepts handled requests
//    16630948 16630948 31070465
//   Reading: 6 Writing: 179 Waiting: 106
//
// Emite 7 métricas por tick:
//   - nginx.connections_active     (gauge)
//   - nginx.connections_reading    (gauge)
//   - nginx.connections_writing    (gauge)
//   - nginx.connections_waiting    (gauge)
//   - nginx.accepted_total         (counter, cumulative)
//   - nginx.handled_total          (counter, cumulative)
//   - nginx.requests_total         (counter, cumulative)
//
// Compatível com framework Phase 2 (checks.Check + Registry + Runtime).
package checks

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultNginxStatusURL = "http://127.0.0.1/nginx_status"
	nginxHTTPTimeout      = 5 * time.Second
)

// Regex pacote-level (RESEARCH §Pattern 5). MustCompile pra falha cedo
// caso o pattern seja editado errado.
var (
	reNginxActive = regexp.MustCompile(`Active connections:\s+(\d+)`)
	// Counts vem na linha sozinha "  N N N" (accepts handled requests).
	reNginxCounts = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\d+)\s*$`)
	reNginxStates = regexp.MustCompile(`Reading:\s+(\d+)\s+Writing:\s+(\d+)\s+Waiting:\s+(\d+)`)
)

// nginxServer é a implementação concreta de Check para "nginx.server".
type nginxServer struct {
	id         string
	interval   time.Duration
	hostID     string
	url        string
	staticTags map[string]string
	client     *http.Client
}

// newNginxServerCheck é a Factory registrada em init() para "nginx.server".
// Param `url` é opcional — default http://127.0.0.1/nginx_status (loopback,
// trust boundary é o host local).
func newNginxServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	url := params["url"]
	if url == "" {
		url = defaultNginxStatusURL
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "nginx.server-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &nginxServer{
		id:         id,
		interval:   interval,
		hostID:     cfg.GetHostId(),
		url:        url,
		staticTags: tags,
		client:     &http.Client{Timeout: nginxHTTPTimeout},
	}, nil
}

func (c *nginxServer) ID() string              { return c.id }
func (c *nginxServer) Interval() time.Duration { return c.interval }
func (c *nginxServer) Tags() map[string]string { return c.staticTags }

// Run faz GET no stub_status, parseia o body e emite 7 métricas. Erro de
// rede/status != 200 retorna err sem emitir nenhuma métrica (scheduler
// Phase 2 conta como check_error e pode disparar circuit-break).
func (c *nginxServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("nginx.server: build request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nginx.server: GET %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nginx.server: stub_status returned %d", resp.StatusCode)
	}

	var (
		active, reading, writing, waiting int64
		accepts, handled, requests        int64
		gotActive, gotCounts, gotStates   bool
	)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !gotActive {
			if m := reNginxActive.FindStringSubmatch(line); m != nil {
				active, _ = strconv.ParseInt(m[1], 10, 64)
				gotActive = true
				continue
			}
		}
		if !gotStates {
			if m := reNginxStates.FindStringSubmatch(line); m != nil {
				reading, _ = strconv.ParseInt(m[1], 10, 64)
				writing, _ = strconv.ParseInt(m[2], 10, 64)
				waiting, _ = strconv.ParseInt(m[3], 10, 64)
				gotStates = true
				continue
			}
		}
		if !gotCounts {
			// Counts é a linha "N N N" — ignora a label-line "server accepts handled requests"
			if strings.Contains(line, "accepts") {
				continue
			}
			if m := reNginxCounts.FindStringSubmatch(line); m != nil {
				accepts, _ = strconv.ParseInt(m[1], 10, 64)
				handled, _ = strconv.ParseInt(m[2], 10, 64)
				requests, _ = strconv.ParseInt(m[3], 10, 64)
				gotCounts = true
				continue
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nginx.server: read body: %w", err)
	}
	if !gotActive || !gotStates || !gotCounts {
		return nil, fmt.Errorf("nginx.server: incomplete stub_status (active=%v counts=%v states=%v)",
			gotActive, gotCounts, gotStates)
	}

	now := timestamppb.Now()
	return []*collectorv1.Metric{
		c.metric(now, "nginx.connections_active", float64(active)),
		c.metric(now, "nginx.connections_reading", float64(reading)),
		c.metric(now, "nginx.connections_writing", float64(writing)),
		c.metric(now, "nginx.connections_waiting", float64(waiting)),
		c.metric(now, "nginx.accepted_total", float64(accepts)),
		c.metric(now, "nginx.handled_total", float64(handled)),
		c.metric(now, "nginx.requests_total", float64(requests)),
	}, nil
}

// metric constrói um Metric com staticTags do CheckConfig + Source fixo.
func (c *nginxServer) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "nginx.server",
	}
}

// init auto-registra o factory em Default.
func init() {
	Default.Register("nginx.server", newNginxServerCheck)
}
