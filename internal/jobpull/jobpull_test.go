package jobpull

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecuteBlocksMutatingCommandBeforeSSH(t *testing.T) {
	result := execute(context.Background(), job{
		Vendor: "cisco", Command: "configure terminal", Host: "127.0.0.1",
	})
	if result["success"] != false {
		t.Fatalf("expected blocked command to fail, got %#v", result)
	}
}

func TestPostResultUsesCollectorIdentityAndAcknowledges(t *testing.T) {
	var path, query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ack":true}`))
	}))
	defer server.Close()

	cfg := Config{Endpoint: server.URL, TenantID: "42", CollectorID: "collector-1", HTTPClient: server.Client()}
	if err := postResult(context.Background(), cfg, completed{
		id: "job-1", result: map[string]any{"success": true},
	}); err != nil {
		t.Fatal(err)
	}
	if path != "/api/collector/v1/jobs/job-1/result" {
		t.Fatalf("unexpected path %q", path)
	}
	if query != "tenant_id=42&collector_id=collector-1" {
		t.Fatalf("unexpected query %q", query)
	}
}
