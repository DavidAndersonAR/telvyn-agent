package checks

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// countingCheck is a test double that tracks how many times Run was called
// and optionally delegates to a custom runFunc.
type countingCheck struct {
	id       string
	interval time.Duration
	runs     atomic.Int32
	runFunc  func(ctx context.Context) ([]*collectorv1.Metric, error)
}

func (c *countingCheck) ID() string              { return c.id }
func (c *countingCheck) Interval() time.Duration { return c.interval }
func (c *countingCheck) Tags() map[string]string { return nil }
func (c *countingCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	c.runs.Add(1)
	if c.runFunc != nil {
		return c.runFunc(ctx)
	}
	return nil, nil
}

func makeRuntime(ctx context.Context, reg *Registry) (*Runtime, chan []*collectorv1.Metric) {
	out := make(chan []*collectorv1.Metric, 64)
	rt := New(ctx, slog.Default(), reg, out)
	return rt, out
}

func cfgFor(checkID, checkType string, interval time.Duration) *collectorv1.CheckConfig {
	return &collectorv1.CheckConfig{
		CheckId:   checkID,
		CheckType: checkType,
		Interval:  durationpb.New(interval),
		Enabled:   true,
	}
}

// TestRuntime_Reload_StartsCheck verifies that Reload starts a goroutine that
// calls Run at least twice within the given time window.
func TestRuntime_Reload_StartsCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	target := &countingCheck{id: "c1", interval: 50 * time.Millisecond}
	reg.Register("stub", func(_ *collectorv1.CheckConfig) (Check, error) { return target, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("c1", "stub", 50*time.Millisecond)})
	time.Sleep(250 * time.Millisecond)
	rt.Reload(nil) // tear down

	if got := target.runs.Load(); got < 2 {
		t.Errorf("expected >= 2 runs, got %d", got)
	}
}

// TestRuntime_Reload_CancelsPreviousGeneration verifies that a second Reload
// stops the first generation's goroutines before starting the new ones.
func TestRuntime_Reload_CancelsPreviousGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	first := &countingCheck{id: "first", interval: 20 * time.Millisecond}
	second := &countingCheck{id: "second", interval: 20 * time.Millisecond}

	reg.Register("first", func(_ *collectorv1.CheckConfig) (Check, error) { return first, nil })
	reg.Register("second", func(_ *collectorv1.CheckConfig) (Check, error) { return second, nil })

	rt, _ := makeRuntime(ctx, reg)

	// Start first generation.
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("first", "first", 20*time.Millisecond)})
	time.Sleep(80 * time.Millisecond)
	firstRuns := first.runs.Load()

	// Replace with second generation.
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("second", "second", 20*time.Millisecond)})
	time.Sleep(80 * time.Millisecond)
	rt.Reload(nil)

	// First should not have grown much after the second Reload.
	firstRunsAfter := first.runs.Load()
	if firstRunsAfter > firstRuns+2 {
		t.Errorf("first generation kept running: runs before=%d after=%d", firstRuns, firstRunsAfter)
	}
	if got := second.runs.Load(); got < 2 {
		t.Errorf("second generation did not start: runs=%d", got)
	}
}

// TestRuntime_ReloadServerDriven_KeepCurrentOnEmpty verifies that an empty
// check generation from the server (e.g. Quarkus mid-restart) does NOT tear
// down the running checks — they keep ticking (Task 2, keep-current-on-empty).
func TestRuntime_ReloadServerDriven_KeepCurrentOnEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	target := &countingCheck{id: "keep", interval: 20 * time.Millisecond}
	reg.Register("keep", func(_ *collectorv1.CheckConfig) (Check, error) { return target, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.ReloadServerDriven([]*collectorv1.CheckConfig{cfgFor("keep", "keep", 20*time.Millisecond)})
	time.Sleep(80 * time.Millisecond)
	before := target.runs.Load()
	if before < 2 {
		t.Fatalf("check did not start: runs=%d", before)
	}

	// Empty generation arrives — must KEEP the check running.
	rt.ReloadServerDriven(nil)
	time.Sleep(120 * time.Millisecond)
	after := target.runs.Load()
	rt.Reload(nil) // intentional teardown

	if after <= before {
		t.Fatalf("check stopped after empty server generation: before=%d after=%d (keep-current-on-empty violated)", before, after)
	}
}

// TestRuntime_ReloadServerDriven_NonEmptySwaps verifies a NEW non-empty
// generation swaps the running set (new check runs, old one stops).
func TestRuntime_ReloadServerDriven_NonEmptySwaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	first := &countingCheck{id: "first", interval: 20 * time.Millisecond}
	second := &countingCheck{id: "second", interval: 20 * time.Millisecond}
	reg.Register("first", func(_ *collectorv1.CheckConfig) (Check, error) { return first, nil })
	reg.Register("second", func(_ *collectorv1.CheckConfig) (Check, error) { return second, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.ReloadServerDriven([]*collectorv1.CheckConfig{cfgFor("first", "first", 20*time.Millisecond)})
	time.Sleep(80 * time.Millisecond)
	firstBefore := first.runs.Load()

	rt.ReloadServerDriven([]*collectorv1.CheckConfig{cfgFor("second", "second", 20*time.Millisecond)})
	time.Sleep(80 * time.Millisecond)
	rt.Reload(nil)

	if second.runs.Load() < 2 {
		t.Errorf("new generation did not start: second runs=%d", second.runs.Load())
	}
	if first.runs.Load() > firstBefore+2 {
		t.Errorf("old generation kept running after swap: before=%d after=%d", firstBefore, first.runs.Load())
	}
}

// TestRuntime_Reload_EmptyList_CancelsAll verifies that Reload(nil) stops
// all running goroutines within a short time.
func TestRuntime_Reload_EmptyList_CancelsAll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	target := &countingCheck{id: "x", interval: 20 * time.Millisecond}
	reg.Register("x", func(_ *collectorv1.CheckConfig) (Check, error) { return target, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("x", "x", 20*time.Millisecond)})
	time.Sleep(60 * time.Millisecond)

	// Snapshot then cancel.
	runsBefore := target.runs.Load()
	rt.Reload(nil) // must finish synchronously (cancel + Wait)

	// Goroutines must have stopped — runs should not grow after Reload(nil).
	time.Sleep(60 * time.Millisecond)
	if after := target.runs.Load(); after > runsBefore+1 {
		t.Errorf("goroutines still running after Reload(nil): before=%d after=%d", runsBefore, after)
	}
}

func TestRuntime_Reload_DoesNotDeadlockWhenCanceledCheckEmits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	started := make(chan struct{})
	var startedClosed atomic.Bool
	first := &countingCheck{
		id:       "first",
		interval: time.Hour,
		runFunc: func(ctx context.Context) ([]*collectorv1.Metric, error) {
			if startedClosed.CompareAndSwap(false, true) {
				close(started)
			}
			<-ctx.Done()
			return []*collectorv1.Metric{{MetricName: "late.metric", HostId: "h1", Source: "test"}}, nil
		},
	}
	second := &countingCheck{id: "second", interval: time.Hour}

	reg.Register("first", func(_ *collectorv1.CheckConfig) (Check, error) { return first, nil })
	reg.Register("second", func(_ *collectorv1.CheckConfig) (Check, error) { return second, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.stopTimeout = 100 * time.Millisecond
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("first", "first", time.Hour)})

	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first check did not start")
	}

	done := make(chan struct{})
	go func() {
		rt.Reload([]*collectorv1.CheckConfig{cfgFor("second", "second", time.Hour)})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Reload deadlocked while stopping a canceled check")
	}
	rt.Reload(nil)
}

func TestRuntime_Reload_TimesOutWaitingForStuckCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	started := make(chan struct{})
	var startedClosed atomic.Bool
	stuck := &countingCheck{
		id:       "stuck",
		interval: time.Hour,
		runFunc: func(_ context.Context) ([]*collectorv1.Metric, error) {
			if startedClosed.CompareAndSwap(false, true) {
				close(started)
			}
			select {}
		},
	}

	reg.Register("stuck", func(_ *collectorv1.CheckConfig) (Check, error) { return stuck, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.stopTimeout = 25 * time.Millisecond
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("stuck", "stuck", time.Hour)})

	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stuck check did not start")
	}

	done := make(chan struct{})
	go func() {
		rt.Reload(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Reload did not honor stop timeout")
	}
}

func TestRuntime_RunContextHasDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	deadlineCheck := &countingCheck{
		id:       "deadline",
		interval: time.Hour,
		runFunc: func(ctx context.Context) ([]*collectorv1.Metric, error) {
			if _, ok := ctx.Deadline(); !ok {
				return nil, errors.New("missing deadline")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	reg.Register("deadline", func(_ *collectorv1.CheckConfig) (Check, error) { return deadlineCheck, nil })

	rt, out := makeRuntime(ctx, reg)
	rt.minRunTimeout = 25 * time.Millisecond
	rt.maxRunTimeout = 25 * time.Millisecond
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("deadline", "deadline", time.Hour)})

	select {
	case metrics := <-out:
		found := false
		for _, m := range metrics {
			if m.MetricName == "ispwatch.check.errors" && m.Tags["check_id"] == "deadline" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected check error metric, got %#v", metrics)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for deadline error metric")
	}
	rt.Reload(nil)
}

// TestRuntime_Reload_DisabledChecks_Skipped verifies that disabled CheckConfigs
// do not spawn goroutines.
func TestRuntime_Reload_DisabledChecks_Skipped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	target := &countingCheck{id: "disabled", interval: 20 * time.Millisecond}
	reg.Register("disabled", func(_ *collectorv1.CheckConfig) (Check, error) { return target, nil })

	rt, _ := makeRuntime(ctx, reg)
	cfg := cfgFor("disabled", "disabled", 20*time.Millisecond)
	cfg.Enabled = false
	rt.Reload([]*collectorv1.CheckConfig{cfg})
	time.Sleep(60 * time.Millisecond)
	rt.Reload(nil)

	if got := target.runs.Load(); got != 0 {
		t.Errorf("disabled check was run %d times, expected 0", got)
	}
}

// TestRuntime_Reload_UnknownType_LogsAndSkips verifies that an unknown check_type
// does not prevent other checks in the same generation from running.
func TestRuntime_Reload_UnknownType_LogsAndSkips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	known := &countingCheck{id: "known", interval: 20 * time.Millisecond}
	reg.Register("known", func(_ *collectorv1.CheckConfig) (Check, error) { return known, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.Reload([]*collectorv1.CheckConfig{
		cfgFor("unknown-check", "does.not.exist", 20*time.Millisecond),
		cfgFor("known-check", "known", 20*time.Millisecond),
	})
	time.Sleep(80 * time.Millisecond)
	rt.Reload(nil)

	if got := known.runs.Load(); got < 2 {
		t.Errorf("known check should have run >= 2 times, got %d", got)
	}
}

// TestRuntime_RunError_EmitsCheckErrorMetric verifies that when Run() returns
// an error, a meta-metric "ispwatch.check.errors" with tag check_id is emitted
// on the out channel.
func TestRuntime_RunError_EmitsCheckErrorMetric(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	errCheck := &countingCheck{
		id:       "failing",
		interval: 20 * time.Millisecond,
		runFunc: func(_ context.Context) ([]*collectorv1.Metric, error) {
			return nil, errors.New("simulated error")
		},
	}
	reg.Register("failing", func(_ *collectorv1.CheckConfig) (Check, error) { return errCheck, nil })

	rt, out := makeRuntime(ctx, reg)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("failing", "failing", 20*time.Millisecond)})

	// Wait for at least one error metric.
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case metrics := <-out:
			for _, m := range metrics {
				if m.MetricName == "ispwatch.check.errors" {
					if m.Tags["check_id"] == "failing" {
						rt.Reload(nil)
						return // test passed
					}
				}
			}
		case <-deadline:
			rt.Reload(nil)
			t.Fatal("timeout: did not receive ispwatch.check.errors metric")
		}
	}
}

// TestRuntime_RunError_CircuitBreak_After5Consecutive verifies that after 5
// consecutive errors, the Runtime skips subsequent Run() calls (circuit-break).
func TestRuntime_RunError_CircuitBreak_After5Consecutive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	errCheck := &countingCheck{
		id:       "circuit",
		interval: 10 * time.Millisecond,
		runFunc: func(_ context.Context) ([]*collectorv1.Metric, error) {
			return nil, errors.New("always fails")
		},
	}
	reg.Register("circuit", func(_ *collectorv1.CheckConfig) (Check, error) { return errCheck, nil })

	rt, _ := makeRuntime(ctx, reg)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("circuit", "circuit", 10*time.Millisecond)})

	// Let it run for much longer than 5 ticks to trigger circuit-break.
	// After circuit-break, runs should plateau.
	time.Sleep(300 * time.Millisecond)
	runsAtCircuit := errCheck.runs.Load()
	time.Sleep(100 * time.Millisecond)
	runsAfter := errCheck.runs.Load()
	rt.Reload(nil)

	// After circuit-break, run count should not grow (or grow very little).
	// Allow up to 1 extra run for timing jitter.
	if runsAfter > runsAtCircuit+1 {
		t.Errorf("circuit-break not active: runs at %dms=%d, at +100ms=%d",
			300, runsAtCircuit, runsAfter)
	}
	// But we should have run exactly circuitBreakThreshold times (5).
	if runsAtCircuit < circuitBreakThreshold {
		t.Errorf("circuit-break triggered too early: only %d runs before break", runsAtCircuit)
	}
}

// TestRuntime_SetTagger_FiltersOverBudget verifica que o Runtime, depois de
// SetTagger com budget=2, filtra as séries que excedem o budget e ainda assim
// faz chegar a meta-métrica `ispwatch.tagger.dropped` no canal out.
func TestRuntime_SetTagger_FiltersOverBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	emitter := &countingCheck{
		id:       "tagger-test",
		interval: 30 * time.Millisecond,
		runFunc: func(_ context.Context) ([]*collectorv1.Metric, error) {
			// Emite 4 séries únicas por tick (budget=2 → 2 kept + 2 drop meta-metrics).
			return []*collectorv1.Metric{
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth0"}, Source: "test"},
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth1"}, Source: "test"},
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth2"}, Source: "test"},
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth3"}, Source: "test"},
			}, nil
		},
	}
	reg.Register("tagger", func(_ *collectorv1.CheckConfig) (Check, error) { return emitter, nil })

	rt, out := makeRuntime(ctx, reg)
	rt.SetTagger(NewTagger(2, slog.Default()))
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("tagger-test", "tagger", 30*time.Millisecond)})

	deadline := time.After(500 * time.Millisecond)
	gotDrop := false
	gotKept := false
	for !gotDrop || !gotKept {
		select {
		case metrics := <-out:
			for _, m := range metrics {
				if m.MetricName == "ispwatch.tagger.dropped" {
					gotDrop = true
				}
				if m.MetricName == "snmp.iface.in" {
					gotKept = true
				}
			}
		case <-deadline:
			rt.Reload(nil)
			t.Fatalf("timeout: gotKept=%v gotDrop=%v", gotKept, gotDrop)
		}
	}
	rt.Reload(nil)
}

// TestRuntime_NilTagger_Passthrough verifica que um Runtime sem SetTagger
// continua emitindo todas as métricas (defensive nil-check em emit).
func TestRuntime_NilTagger_Passthrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	emitter := &countingCheck{
		id:       "no-tagger",
		interval: 30 * time.Millisecond,
		runFunc: func(_ context.Context) ([]*collectorv1.Metric, error) {
			return []*collectorv1.Metric{
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth0"}, Source: "test"},
				{MetricName: "snmp.iface.in", HostId: "h1", Tags: map[string]string{"iface": "eth1"}, Source: "test"},
			}, nil
		},
	}
	reg.Register("no-tagger", func(_ *collectorv1.CheckConfig) (Check, error) { return emitter, nil })

	rt, out := makeRuntime(ctx, reg)
	// SEM SetTagger.
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("no-tagger", "no-tagger", 30*time.Millisecond)})

	select {
	case metrics := <-out:
		if len(metrics) != 2 {
			t.Errorf("nil tagger: kept=%d, want 2 (passthrough)", len(metrics))
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timeout waiting for metrics from passthrough runtime")
	}
	rt.Reload(nil)
}
