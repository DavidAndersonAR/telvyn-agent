package scheduler

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ispwatch/collector/internal/tools"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// stubExecutor is a Tool that records calls and returns a fixed result.
type stubExecutor struct {
	name   string
	calls  atomic.Int32
	result map[string]any
	err    error
}

func (s *stubExecutor) Name() string { return s.name }

func (s *stubExecutor) Execute(_ context.Context, _ map[string]any) (map[string]any, error) {
	s.calls.Add(1)
	return s.result, s.err
}

func newRegistryWith(execs ...*stubExecutor) *tools.Registry {
	r := tools.NewRegistry()
	for _, e := range execs {
		r.Register(e)
	}
	return r
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb: %v", err)
	}
	return s
}

func TestScheduler_RunOnce_NoTicker(t *testing.T) {
	exec := &stubExecutor{
		name: "snmp.get",
		result: map[string]any{"metrics": []any{
			map[string]any{"name": "cpu", "value": 7.5, "source": "snmp"},
		}},
	}
	out := make(chan []*collectorv1.Metric, 4)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)

	r.Reload([]*collectorv1.ScheduledJob{{
		JobId: "j1", Tool: "snmp.get", IntervalSeconds: 0, HostId: "ccr1036", Enabled: true,
	}})

	select {
	case batch := <-out:
		if len(batch) != 1 || batch[0].MetricName != "cpu" || batch[0].HostId != "ccr1036" {
			t.Fatalf("unexpected batch: %+v", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no metric emitted within timeout")
	}

	// Wait briefly to confirm no second invocation happens (interval<=0).
	time.Sleep(150 * time.Millisecond)
	if got := exec.calls.Load(); got != 1 {
		t.Fatalf("expected single fire, got %d", got)
	}
}

func TestScheduler_DisabledJobsSkipped(t *testing.T) {
	exec := &stubExecutor{name: "snmp.get", result: map[string]any{"metrics": []any{}}}
	out := make(chan []*collectorv1.Metric, 4)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)

	r.Reload([]*collectorv1.ScheduledJob{{
		JobId: "off", Tool: "snmp.get", Enabled: false,
	}})

	time.Sleep(100 * time.Millisecond)
	if got := exec.calls.Load(); got != 0 {
		t.Fatalf("disabled job fired %d times", got)
	}
}

func TestScheduler_UnknownToolSkipped(t *testing.T) {
	exec := &stubExecutor{name: "snmp.get", result: map[string]any{}}
	out := make(chan []*collectorv1.Metric, 4)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)
	r.Reload([]*collectorv1.ScheduledJob{{
		JobId: "x", Tool: "nope.unknown", Enabled: true,
	}})
	time.Sleep(100 * time.Millisecond)
	if got := exec.calls.Load(); got != 0 {
		t.Fatalf("unknown-tool job fired %d times", got)
	}
}

func TestScheduler_ReloadCancelsPrevious(t *testing.T) {
	exec := &stubExecutor{
		name:   "snmp.get",
		result: map[string]any{"metrics": []any{map[string]any{"name": "cpu", "value": 1.0}}},
	}
	out := make(chan []*collectorv1.Metric, 32)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)

	// 1st gen: tight ticker.
	r.Reload([]*collectorv1.ScheduledJob{{
		JobId: "g1", Tool: "snmp.get", IntervalSeconds: 1, Enabled: true,
	}})
	time.Sleep(50 * time.Millisecond)
	first := exec.calls.Load() // probably 1 (the immediate fire)

	// 2nd gen: empty list — must cancel everything.
	r.Reload(nil)
	time.Sleep(1500 * time.Millisecond) // longer than the 1s ticker
	if got := exec.calls.Load(); got != first {
		t.Fatalf("calls grew after empty reload: was %d, now %d (ticker should've been cancelled)", first, got)
	}
}

// TestScheduler_ReloadServerDriven_KeepCurrentOnEmpty verifies that an empty
// generation from the server (e.g. Quarkus mid-restart) does NOT tear down the
// running jobs — the ticker keeps firing (Task 2, keep-current-on-empty).
func TestScheduler_ReloadServerDriven_KeepCurrentOnEmpty(t *testing.T) {
	exec := &stubExecutor{
		name:   "snmp.get",
		result: map[string]any{"metrics": []any{map[string]any{"name": "cpu", "value": 1.0}}},
	}
	out := make(chan []*collectorv1.Metric, 64)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)

	// Apply a non-empty generation with a tight ticker.
	r.ReloadServerDriven([]*collectorv1.ScheduledJob{{
		JobId: "g1", Tool: "snmp.get", IntervalSeconds: 1, Enabled: true,
	}})
	time.Sleep(50 * time.Millisecond)
	before := exec.calls.Load()
	if before < 1 {
		t.Fatalf("expected at least the immediate fire, got %d", before)
	}

	// Empty generation arrives — must KEEP current jobs running.
	r.ReloadServerDriven(nil)
	time.Sleep(1500 * time.Millisecond) // longer than the 1s ticker

	after := exec.calls.Load()
	if after <= before {
		t.Fatalf("ticker stopped after empty server generation: before=%d after=%d (keep-current-on-empty violated)", before, after)
	}
}

// TestScheduler_ReloadServerDriven_NonEmptySwaps verifies a NEW non-empty
// generation swaps the running set (the new job runs, replacing the old one).
func TestScheduler_ReloadServerDriven_NonEmptySwaps(t *testing.T) {
	execA := &stubExecutor{name: "snmp.get", result: map[string]any{"metrics": []any{map[string]any{"name": "a", "value": 1.0}}}}
	execB := &stubExecutor{name: "snmp.walk", result: map[string]any{"metrics": []any{map[string]any{"name": "b", "value": 2.0}}}}
	out := make(chan []*collectorv1.Metric, 64)
	r := New(context.Background(), slog.Default(), newRegistryWith(execA, execB), out)

	r.ReloadServerDriven([]*collectorv1.ScheduledJob{{
		JobId: "a", Tool: "snmp.get", IntervalSeconds: 0, Enabled: true,
	}})
	time.Sleep(100 * time.Millisecond)
	aCalls := execA.calls.Load()

	// Swap to a different job set.
	r.ReloadServerDriven([]*collectorv1.ScheduledJob{{
		JobId: "b", Tool: "snmp.walk", IntervalSeconds: 0, Enabled: true,
	}})
	time.Sleep(100 * time.Millisecond)

	if execB.calls.Load() < 1 {
		t.Fatalf("new generation did not run: execB calls=%d", execB.calls.Load())
	}
	// Old run-once job should not have fired again after the swap.
	if execA.calls.Load() != aCalls {
		t.Errorf("old job fired after swap: was %d now %d", aCalls, execA.calls.Load())
	}
}

func TestScheduler_MetricExtraction_TagsAndOverrides(t *testing.T) {
	exec := &stubExecutor{
		name: "snmp.walk",
		result: map[string]any{"metrics": []any{
			map[string]any{
				"name": "net.if.in", "value": 12345.0,
				"source": "snmp", "interface_name": "eth0",
				"host_id": "override.example.com",
				"tags":    map[string]any{"oid": "1.3.6.1.2.1.2.2.1.10.2"},
			},
		}},
	}
	out := make(chan []*collectorv1.Metric, 4)
	r := New(context.Background(), slog.Default(), newRegistryWith(exec), out)
	r.Reload([]*collectorv1.ScheduledJob{{
		JobId: "w1", Tool: "snmp.walk", IntervalSeconds: 0, HostId: "default-host", Enabled: true,
		Args: mustStruct(t, map[string]any{}),
	}})
	select {
	case batch := <-out:
		if len(batch) != 1 {
			t.Fatalf("want 1 metric, got %d", len(batch))
		}
		m := batch[0]
		if m.HostId != "override.example.com" {
			t.Errorf("host_id override lost: %s", m.HostId)
		}
		if m.InterfaceName != "eth0" || m.Source != "snmp" {
			t.Errorf("iface/source lost: iface=%s source=%s", m.InterfaceName, m.Source)
		}
		if m.Tags["oid"] != "1.3.6.1.2.1.2.2.1.10.2" {
			t.Errorf("tag lost: %v", m.Tags)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for metric")
	}
}
