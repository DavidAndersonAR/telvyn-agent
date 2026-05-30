package checks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const nginxCanonicalBody = `Active connections: 291
server accepts handled requests
 16630948 16630948 31070465
Reading: 6 Writing: 179 Waiting: 106
`

func newNginxStubServer(t *testing.T, status int, body string, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
}

func TestNginxServer_FactoryDefaultsUrl(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "nginx.server",
		HostId:    "host-1",
		Params:    map[string]string{},
	}
	c, err := newNginxServerCheck(cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	ns, ok := c.(*nginxServer)
	if !ok {
		t.Fatalf("expected *nginxServer; got %T", c)
	}
	if ns.url != "http://127.0.0.1/nginx_status" {
		t.Errorf("expected default url=http://127.0.0.1/nginx_status; got %q", ns.url)
	}
	if c.Interval() != 30*time.Second {
		t.Errorf("expected default Interval=30s; got %v", c.Interval())
	}
	if c.ID() != "nginx.server-host-1" {
		t.Errorf("expected default ID=nginx.server-host-1; got %q", c.ID())
	}
}

func TestNginxServer_FactoryAcceptsCustomUrl(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "nginx.server",
		HostId:    "host-1",
		Params:    map[string]string{"url": "http://10.0.0.5:8080/status"},
	}
	c, err := newNginxServerCheck(cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	ns := c.(*nginxServer)
	if ns.url != "http://10.0.0.5:8080/status" {
		t.Errorf("expected custom url; got %q", ns.url)
	}
}

func TestNginxServer_RunParsesCanonicalOutput(t *testing.T) {
	srv := newNginxStubServer(t, 200, nginxCanonicalBody, 0)
	defer srv.Close()

	cfg := &collectorv1.CheckConfig{
		CheckType: "nginx.server",
		HostId:    "host-1",
		Interval:  durationpb.New(30 * time.Second),
		Params:    map[string]string{"url": srv.URL},
	}
	c, err := newNginxServerCheck(cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(metrics) < 7 {
		t.Fatalf("expected >=7 metrics; got %d", len(metrics))
	}

	values := map[string]float64{}
	for _, m := range metrics {
		values[m.MetricName] = m.Value
		if m.Source != "nginx.server" {
			t.Errorf("metric %q: expected Source=nginx.server; got %q", m.MetricName, m.Source)
		}
	}

	expect := map[string]float64{
		"nginx.connections_active":  291,
		"nginx.connections_reading": 6,
		"nginx.connections_writing": 179,
		"nginx.connections_waiting": 106,
		"nginx.accepted_total":      16630948,
		"nginx.handled_total":       16630948,
		"nginx.requests_total":      31070465,
	}
	for name, want := range expect {
		got, ok := values[name]
		if !ok {
			t.Errorf("missing metric %q", name)
			continue
		}
		if got != want {
			t.Errorf("metric %q: want %v; got %v", name, want, got)
		}
	}
}

func TestNginxServer_RunRejects500(t *testing.T) {
	srv := newNginxStubServer(t, 500, "internal error", 0)
	defer srv.Close()

	cfg := &collectorv1.CheckConfig{
		CheckType: "nginx.server",
		HostId:    "host-1",
		Params:    map[string]string{"url": srv.URL},
	}
	c, _ := newNginxServerCheck(cfg)
	metrics, err := c.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics on 500; got %d", len(metrics))
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status code; got %v", err)
	}
}

func TestNginxServer_TagsMergeStaticTags(t *testing.T) {
	srv := newNginxStubServer(t, 200, nginxCanonicalBody, 0)
	defer srv.Close()

	cfg := &collectorv1.CheckConfig{
		CheckType:  "nginx.server",
		HostId:     "host-1",
		StaticTags: map[string]string{"role": "nginx", "env": "prod"},
		Params:     map[string]string{"url": srv.URL},
	}
	c, _ := newNginxServerCheck(cfg)
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("no metrics emitted")
	}
	for _, m := range metrics {
		if m.Tags["role"] != "nginx" {
			t.Errorf("metric %q: expected tag role=nginx; got %v", m.MetricName, m.Tags)
		}
		if m.Tags["env"] != "prod" {
			t.Errorf("metric %q: expected tag env=prod; got %v", m.MetricName, m.Tags)
		}
	}
}

func TestNginxServer_TimeoutPropagates(t *testing.T) {
	// Server adiciona delay > ctx timeout pra forçar deadline exceeded.
	srv := newNginxStubServer(t, 200, nginxCanonicalBody, 200*time.Millisecond)
	defer srv.Close()

	cfg := &collectorv1.CheckConfig{
		CheckType: "nginx.server",
		HostId:    "host-1",
		Params:    map[string]string{"url": srv.URL},
	}
	c, _ := newNginxServerCheck(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Run(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context-related error; got %v", err)
	}
}

func TestNginxServer_RegisteredInDefaultRegistry(t *testing.T) {
	if _, ok := Default.Get("nginx.server"); !ok {
		t.Fatal("nginx.server must be registered in Default registry via init()")
	}
}
