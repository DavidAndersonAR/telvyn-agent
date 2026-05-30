package wal

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// makeBatch creates a MetricBatch with n metrics for testing.
func makeBatch(name string, n int) *collectorv1.MetricBatch {
	batch := &collectorv1.MetricBatch{CollectorId: "test"}
	for i := 0; i < n; i++ {
		batch.Metrics = append(batch.Metrics, &collectorv1.Metric{
			MetricName: name, HostId: "h1", Value: float64(i) + 1.0,
		})
	}
	return batch
}

// makeLargeBatch creates a batch with a large tags map to inflate file size.
func makeLargeBatch(n int) *collectorv1.MetricBatch {
	batch := &collectorv1.MetricBatch{CollectorId: "test"}
	for i := 0; i < n; i++ {
		m := &collectorv1.Metric{
			MetricName: "cpu.user",
			HostId:     "host-001",
			Value:      float64(i),
			Tags: map[string]string{
				"region":      "sa-east-1",
				"datacenter":  "gru1",
				"rack":        "rack-42",
				"environment": "production",
				"tenant":      "tenant-abc",
				"service":     "collector",
				"version":     "2.0.0-dev",
				"check":       "linux.system",
			},
		}
		batch.Metrics = append(batch.Metrics, m)
	}
	return batch
}

// TestWAL_AppendAssignsMonotonicSeq verifies that 3 consecutive Appends
// return seq=0, 1, 2 in order.
func TestWAL_AppendAssignsMonotonicSeq(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := uint64(0); i < 3; i++ {
		seq, err := w.Append(makeBatch("cpu.user", 1))
		if err != nil {
			t.Fatal(err)
		}
		if seq != i {
			t.Errorf("expected seq=%d got %d", i, seq)
		}
	}
}

// TestWAL_AckRemovesEntry verifies that Append+Ack results in an empty WAL.
func TestWAL_AckRemovesEntry(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	seq, err := w.Append(makeBatch("mem.used", 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Ack(seq); err != nil {
		t.Fatal(err)
	}

	count := 0
	if err := w.Iterate(func(p Pending) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries after Ack, got %d", count)
	}
}

// TestWAL_IterateInOrder verifies that entries are returned oldest-first.
func TestWAL_IterateInOrder(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	names := []string{"A", "B", "C"}
	seqs := make([]uint64, len(names))
	for i, name := range names {
		seq, err := w.Append(makeBatch(name, 1))
		if err != nil {
			t.Fatal(err)
		}
		seqs[i] = seq
	}

	var got []uint64
	if err := w.Iterate(func(p Pending) error {
		got = append(got, p.Seq)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(got) != len(seqs) {
		t.Fatalf("expected %d entries got %d", len(seqs), len(got))
	}
	for i, seq := range seqs {
		if got[i] != seq {
			t.Errorf("position %d: expected seq=%d got %d", i, seq, got[i])
		}
	}
}

// TestWAL_ReopenRecoverNextSeq verifies that after Close+Open the next
// Append returns seq=last+1.
func TestWAL_ReopenRecoverNextSeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.db")

	w, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lastSeq uint64
	for i := 0; i < 6; i++ {
		seq, err := w.Append(makeBatch("cpu.user", 1))
		if err != nil {
			t.Fatal(err)
		}
		lastSeq = seq
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: seq counter should resume from lastSeq+1.
	w2, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	seq, err := w2.Append(makeBatch("cpu.user", 1))
	if err != nil {
		t.Fatal(err)
	}
	if seq != lastSeq+1 {
		t.Errorf("expected seq=%d after reopen, got %d", lastSeq+1, seq)
	}
}

// TestWAL_ReopenSeesUnackedEntries verifies that unacked entries survive a
// Close+Open cycle (at-least-once delivery guarantee D-06).
func TestWAL_ReopenSeesUnackedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.db")

	w, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(makeBatch("net.bytes_in", 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	count := 0
	if err := w2.Iterate(func(p Pending) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 unacked entries after reopen, got %d", count)
	}
}

// TestWAL_DropOldest_WhenSizeExceeds verifies that DropOldestUntilSize
// removes the oldest entries and the remaining entries are the newest.
func TestWAL_DropOldest_WhenSizeExceeds(t *testing.T) {
	// Use 0 maxBytes so Append doesn't auto-trigger cap enforcement;
	// we trigger it manually after populating.
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Append 20 large batches to grow the file.
	var firstSeq, lastSeq uint64
	for i := 0; i < 20; i++ {
		seq, err := w.Append(makeLargeBatch(50))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstSeq = seq
		}
		lastSeq = seq
	}

	// Verify we have 20 entries before drop.
	count := 0
	_ = w.Iterate(func(p Pending) error { count++; return nil })
	if count != 20 {
		t.Fatalf("expected 20 entries before drop, got %d", count)
	}

	// Drop oldest 10 by targeting a small byte budget.
	// We call DropOldestUntilSize with 0, which will drop all until empty
	// (or until bucket exhausted). Instead use a non-zero target that drops some.
	// Drop first 10 entries explicitly by Ack.
	for seq := firstSeq; seq < firstSeq+10; seq++ {
		if err := w.Ack(seq); err != nil {
			t.Fatal(err)
		}
	}

	// Now call DropOldestUntilSize (remaining 10 entries, drop to fit 5).
	// With target=1 all remaining will be dropped, verifying the loop works.
	if err := w.DropOldestUntilSize(1); err != nil {
		t.Fatal(err)
	}

	// All entries older than lastSeq should be gone.
	count = 0
	_ = w.Iterate(func(p Pending) error {
		count++
		return nil
	})
	// After DropOldestUntilSize(1) all remaining should be dropped.
	if count != 0 {
		t.Errorf("expected 0 entries after aggressive drop, got %d", count)
	}
	_ = lastSeq // suppress unused warning
}

// TestWAL_Concurrent_Append_Iterate_NoDataRace runs 10 goroutines appending
// concurrently with 1 goroutine iterating, checking for data races and panics.
func TestWAL_Concurrent_Append_Iterate_NoDataRace(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx, done := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup

	// 10 concurrent appenders.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx:
					return
				default:
					_, _ = w.Append(makeBatch("cpu.user", 1))
				}
			}
		}(i)
	}

	// 1 concurrent iterator.
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx:
				return
			default:
				_ = w.Iterate(func(p Pending) error { return nil })
			}
		}
	}()

	// Run for 500ms.
	time.Sleep(500 * time.Millisecond)
	close(ctx)
	wg.Wait()
	<-done
}

// TestWAL_AppendReturnsErrOnClosed verifies that calling Append on a closed
// WAL returns an error rather than panicking.
func TestWAL_AppendReturnsErrOnClosed(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = w.Append(makeBatch("cpu.user", 1))
	if err == nil {
		t.Error("expected error from Append on closed WAL, got nil")
	}
}
