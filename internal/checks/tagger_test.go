package checks

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// mkMetric constrói uma Metric simples para os testes do tagger.
func mkMetric(host, name string, tags map[string]string) *collectorv1.Metric {
	return &collectorv1.Metric{
		Time:       timestamppb.Now(),
		HostId:     host,
		MetricName: name,
		Value:      1.0,
		Tags:       tags,
		Source:     "test",
	}
}

// TestTagger_Filter_UnderBudget garante que Filter passa todas as métricas
// quando a quantidade de séries únicas por host está dentro do budget.
func TestTagger_Filter_UnderBudget(t *testing.T) {
	tg := NewTagger(3, slog.Default())

	in := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth2"}),
	}
	kept, drops := tg.Filter(in)
	if len(kept) != 3 {
		t.Errorf("kept: want 3, got %d", len(kept))
	}
	if len(drops) != 0 {
		t.Errorf("drops: want 0, got %d", len(drops))
	}
}

// TestTagger_Filter_OverBudget_DropsExcedente verifica que séries acima do
// budget são dropadas e geram meta-métrica ispwatch.tagger.dropped.
func TestTagger_Filter_OverBudget_DropsExcedente(t *testing.T) {
	tg := NewTagger(3, slog.Default())

	// Primeiro lote enche o budget.
	first := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth2"}),
	}
	if kept, _ := tg.Filter(first); len(kept) != 3 {
		t.Fatalf("setup: expected 3 kept, got %d", len(kept))
	}

	// Quarta série deve ser dropada.
	second := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth3"}),
	}
	kept, drops := tg.Filter(second)
	if len(kept) != 0 {
		t.Errorf("kept: want 0, got %d", len(kept))
	}
	if len(drops) != 1 {
		t.Fatalf("drops: want 1, got %d", len(drops))
	}
	d := drops[0]
	if d.GetMetricName() != "ispwatch.tagger.dropped" {
		t.Errorf("drop metric name: want ispwatch.tagger.dropped, got %q", d.GetMetricName())
	}
	if d.GetTags()["host"] != "hostA" {
		t.Errorf("drop tag host: want hostA, got %q", d.GetTags()["host"])
	}
	if d.GetTags()["metric"] != "snmp.iface.in" {
		t.Errorf("drop tag metric: want snmp.iface.in, got %q", d.GetTags()["metric"])
	}
}

// TestTagger_Filter_RepeatSerie_NaoIncrementaCardinality verifica que repetir
// uma série existente não consome novo slot e ainda atualiza lastSeen.
func TestTagger_Filter_RepeatSerie_NaoIncrementaCardinality(t *testing.T) {
	tg := NewTagger(2, slog.Default())

	in := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	}
	if kept, _ := tg.Filter(in); len(kept) != 2 {
		t.Fatalf("setup: expected 2 kept, got %d", len(kept))
	}

	// Repete eth0 — deve passar sem drop e sem ocupar novo slot.
	repeat := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	}
	kept, drops := tg.Filter(repeat)
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("repeat: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}

	// Como cardinality continua em 2 (e budget=2), uma série nova deve dropar.
	nova := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth9"}),
	}
	_, drops = tg.Filter(nova)
	if len(drops) != 1 {
		t.Errorf("nova depois de repeat: drops=%d, want 1", len(drops))
	}
}

// TestTagger_Filter_BudgetPorHost_IsolaHosts verifica que budgets são contados
// por host — encher hostA não afeta hostB.
func TestTagger_Filter_BudgetPorHost_IsolaHosts(t *testing.T) {
	tg := NewTagger(1, slog.Default())

	// Enche hostA.
	if kept, _ := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	}); len(kept) != 1 {
		t.Fatalf("setup hostA: kept=%d, want 1", len(kept))
	}

	// hostB deve passar mesmo com hostA cheio.
	kept, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostB", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("hostB: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}
}

// TestTagger_Filter_MetaMetric_FastPath verifica que meta-métricas
// (ispwatch.tagger.* e ispwatch.check.*) bypassam o budget — Pitfall 4.
func TestTagger_Filter_MetaMetric_FastPath(t *testing.T) {
	tg := NewTagger(1, slog.Default())

	// Enche o budget de hostA com uma série regular.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})

	// Meta-métricas devem passar mesmo com budget cheio.
	in := []*collectorv1.Metric{
		mkMetric("hostA", "ispwatch.tagger.dropped", map[string]string{"metric": "x"}),
		mkMetric("hostA", "ispwatch.check.errors", map[string]string{"check_id": "y"}),
	}
	kept, drops := tg.Filter(in)
	if len(kept) != 2 {
		t.Errorf("fast-path: kept=%d, want 2", len(kept))
	}
	if len(drops) != 0 {
		t.Errorf("fast-path: drops=%d, want 0", len(drops))
	}
}

// TestTagger_Filter_LazyGC_RemoveEntriesStale verifica que séries não vistas
// há mais que a janela (24h) são purgadas quando o budget aperta.
func TestTagger_Filter_LazyGC_RemoveEntriesStale(t *testing.T) {
	tg := NewTagger(2, slog.Default())

	// Enche o budget.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	})

	// Marca eth0 como stale (> 24h atrás) para forçar GC.
	tg.mu.Lock()
	for k := range tg.seen["hostA"] {
		if strings.Contains(k, "eth0") {
			tg.seen["hostA"][k] = time.Now().Add(-25 * time.Hour)
		}
	}
	tg.mu.Unlock()

	// Nova série deve entrar — eth0 será purgado pelo GC lazy.
	kept, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth9"}),
	})
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("GC: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}
}

// TestTagger_Filter_LogEstruturado_TemCamposObrigatorios verifica que o log
// emitido em drop tem host_id, metric, current_cardinality e budget.
func TestTagger_Filter_LogEstruturado_TemCamposObrigatorios(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	tg := NewTagger(1, logger)

	// Enche.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})
	// Provoca drop.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	})

	// Lê última linha do buffer (JSON por linha).
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("no log lines captured")
	}
	last := lines[len(lines)-1]

	var entry map[string]any
	if err := json.Unmarshal([]byte(last), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v — line=%s", err, last)
	}
	for _, field := range []string{"host_id", "metric", "current_cardinality", "budget"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("log entry missing field %q — entry=%v", field, entry)
		}
	}
	if entry["host_id"] != "hostA" {
		t.Errorf("log host_id: want hostA, got %v", entry["host_id"])
	}
	if entry["metric"] != "snmp.iface.in" {
		t.Errorf("log metric: want snmp.iface.in, got %v", entry["metric"])
	}
}
