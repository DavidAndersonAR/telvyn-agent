package otlp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterCollectorReportsBinaryVersion(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/collector/register" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"collector_id":"11111111-1111-1111-1111-111111111111","tenant":"2"}`)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "host", "cluster", "v0.4.4",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, _, err := exporter.RegisterCollector(context.Background(), "poller", []string{"metrics"}, "docker"); err != nil {
		t.Fatalf("RegisterCollector: %v", err)
	}
	if got := payload["agent_version"]; got != "v0.4.4" {
		t.Fatalf("agent_version = %v, want v0.4.4", got)
	}
	if got := payload["install_mode"]; got != "docker" {
		t.Fatalf("install_mode = %v, want docker", got)
	}
}
