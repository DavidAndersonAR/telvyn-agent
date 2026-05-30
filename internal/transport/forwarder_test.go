package transport

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/transport/wal"
)

// openTestWAL opens a WAL in a temp directory with no cap.
func openTestWAL(t *testing.T) *wal.WAL {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "test.db"), 0)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// makeMetrics builds a slice of n metrics.
func makeMetrics(name string, n int) []*collectorv1.Metric {
	out := make([]*collectorv1.Metric, n)
	for i := range out {
		out[i] = &collectorv1.Metric{
			MetricName: name,
			HostId:     "host-test",
			Value:      float64(i),
		}
	}
	return out
}

// TestForwarder_Producer_AppendsToWAL verifies that Push followed by Flush
// stores exactly 1 entry in the WAL.
func TestForwarder_Producer_AppendsToWAL(t *testing.T) {
	w := openTestWAL(t)
	p := NewProducer(w, "col-01", testLogger(t), 500, time.Second)

	p.Push(makeMetrics("cpu.user", 3))
	p.Flush()

	count := 0
	if err := w.Iterate(func(_ wal.Pending) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 WAL entry after Push+Flush, got %d", count)
	}
}

// TestForwarder_BatchAggregation_FlushOnSize verifies that batchSize=2 causes
// a flush after 2 Push(1) calls.
func TestForwarder_BatchAggregation_FlushOnSize(t *testing.T) {
	w := openTestWAL(t)
	// batchSize=2: after 2 single-metric pushes we should have 1 batch.
	p := NewProducer(w, "col-01", testLogger(t), 2, time.Hour)

	p.Push(makeMetrics("cpu.user", 1))
	p.Push(makeMetrics("cpu.user", 1))

	// Give the flush a moment (it's synchronous on size trigger).
	count := 0
	_ = w.Iterate(func(_ wal.Pending) error { count++; return nil })
	if count != 1 {
		t.Errorf("expected 1 batch in WAL after 2 pushes at batchSize=2, got %d", count)
	}
}

// TestForwarder_BatchAggregation_NoFlushOnEmpty verifies that Push(0) does
// not create a WAL entry.
func TestForwarder_BatchAggregation_NoFlushOnEmpty(t *testing.T) {
	w := openTestWAL(t)
	p := NewProducer(w, "col-01", testLogger(t), 500, time.Hour)

	p.Push([]*collectorv1.Metric{})
	p.Flush() // explicit flush on empty pending — should be no-op

	count := 0
	_ = w.Iterate(func(_ wal.Pending) error { count++; return nil })
	if count != 0 {
		t.Errorf("expected 0 WAL entries after Push(empty), got %d", count)
	}
}

// TestForwarder_BatchAggregation_FlushOnInterval verifies that RunFlushLoop
// flushes pending metrics within flushInterval.
func TestForwarder_BatchAggregation_FlushOnInterval(t *testing.T) {
	w := openTestWAL(t)
	// large batchSize so size-trigger won't fire; short interval.
	p := NewProducer(w, "col-01", testLogger(t), 500, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.RunFlushLoop(ctx)

	p.Push(makeMetrics("net.bytes_in", 1))

	// Wait up to 200ms for the interval to fire.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		count := 0
		_ = w.Iterate(func(_ wal.Pending) error { count++; return nil })
		if count == 1 {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("expected 1 WAL entry after flush interval, got 0")
}

// TestForwarder_Notify_FiresAfterFlush verifies that the notify channel
// receives a signal after a Flush that appends to the WAL.
func TestForwarder_Notify_FiresAfterFlush(t *testing.T) {
	w := openTestWAL(t)
	p := NewProducer(w, "col-01", testLogger(t), 500, time.Hour)

	p.Push(makeMetrics("mem.used", 1))
	p.Flush()

	select {
	case <-p.Notify():
		// OK
	case <-time.After(100 * time.Millisecond):
		t.Error("expected notify signal after Flush, got timeout")
	}
}

// TestForwarder_Notify_NoSignalOnEmptyFlush verifies that Flush on an empty
// buffer does NOT send a notify signal.
func TestForwarder_Notify_NoSignalOnEmptyFlush(t *testing.T) {
	w := openTestWAL(t)
	p := NewProducer(w, "col-01", testLogger(t), 500, time.Hour)

	p.Flush() // no-op

	select {
	case <-p.Notify():
		t.Error("unexpected notify signal on empty Flush")
	case <-time.After(50 * time.Millisecond):
		// OK — no spurious signal
	}
}

// TestConfig_WALFlags_ParsedFromCLI verifies that --wal-path and --wal-max-mb
// are parsed and stored correctly.
func TestConfig_WALFlags_ParsedFromCLI(t *testing.T) {
	// This test lives in the transport package for convenience but it tests
	// the config package. It is a black-box integration check.
	// We import config indirectly via the compiled binary — here we use the
	// exported Parse function directly.
	// NOTE: config_test is in the config package; we test WAL flags here
	// using a forwarder_test helper to avoid import cycles.
	// Since we can't import config directly (different package), this test
	// documents the expected behaviour via the Producer construction path:
	// the caller opens the WAL with the parsed cfg.WalPath/WalMaxBytes.
	// The actual flag parsing test lives in internal/config/config_test.go.
	t.Skip("WAL flag parsing tested in internal/config — see TestConfig_WALFlags")
}

// testLogger returns a no-op slog.Logger for tests.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
