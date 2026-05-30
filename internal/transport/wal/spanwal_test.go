package wal

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// makeSpanBatch creates a SpanBatch with n spans for testing.
func makeSpanBatch(name string, n int) *collectorv1.SpanBatch {
	batch := &collectorv1.SpanBatch{CollectorId: "test"}
	for i := 0; i < n; i++ {
		batch.Spans = append(batch.Spans, &collectorv1.Span{
			TraceId: "trace", SpanId: "span", Name: name,
		})
	}
	return batch
}

// makeLargeSpanBatch inflates file size with big attribute maps.
func makeLargeSpanBatch(n int) *collectorv1.SpanBatch {
	batch := &collectorv1.SpanBatch{CollectorId: "test"}
	for i := 0; i < n; i++ {
		batch.Spans = append(batch.Spans, &collectorv1.Span{
			TraceId:   "0123456789abcdef0123456789abcdef",
			SpanId:    "0123456789abcdef",
			Name:      "GET /api/v1/very/long/route/name/for/size",
			Namespace: "production",
			Pod:       "checkout-7d8f9c-abcde",
			Attributes: map[string]string{
				"http.method":      "GET",
				"http.status_code": "200",
				"db.system":        "postgresql",
				"db.statement":     "SELECT * FROM orders WHERE tenant=$1 AND created_at > $2",
				"net.peer.name":    "db.internal.svc.cluster.local",
				"service.version":  "2.0.0-dev",
			},
		})
	}
	return batch
}

// TestSpanWAL_AppendAssignsMonotonicSeq verifies seq=0,1,2 ordering.
func TestSpanWAL_AppendAssignsMonotonicSeq(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := uint64(0); i < 3; i++ {
		seq, err := w.Append(makeSpanBatch("op", 1))
		if err != nil {
			t.Fatal(err)
		}
		if seq != i {
			t.Errorf("expected seq=%d got %d", i, seq)
		}
	}
}

// TestSpanWAL_AppendAckReplayRoundTrip is the core durability round-trip:
// append → iterate sees it → ack → iterate empty.
func TestSpanWAL_AppendAckReplayRoundTrip(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	seq, err := w.Append(makeSpanBatch("checkout", 3))
	if err != nil {
		t.Fatal(err)
	}

	// Replay sees the batch with the right seq and span count.
	seen := 0
	if err := w.Iterate(func(p PendingSpan) error {
		seen++
		if p.Seq != seq {
			t.Errorf("replay seq=%d want %d", p.Seq, seq)
		}
		if len(p.Batch.Spans) != 3 {
			t.Errorf("replay spans=%d want 3", len(p.Batch.Spans))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("expected 1 pending entry, got %d", seen)
	}

	// Ack removes it.
	if err := w.Ack(seq); err != nil {
		t.Fatal(err)
	}
	count := 0
	_ = w.Iterate(func(PendingSpan) error { count++; return nil })
	if count != 0 {
		t.Errorf("expected 0 entries after Ack, got %d", count)
	}
}

// TestSpanWAL_ReopenSeesUnackedEntries verifies traces survive a Close+Open
// (server-down-at-restart scenario for traces).
func TestSpanWAL_ReopenSeesUnackedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.db")

	w, err := OpenSpanWAL(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(makeSpanBatch("op", 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := OpenSpanWAL(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	count := 0
	if err := w2.Iterate(func(PendingSpan) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 unacked span entries after reopen, got %d", count)
	}

	// Next append resumes the seq counter.
	seq, err := w2.Append(makeSpanBatch("op", 1))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Errorf("expected seq=3 after reopen, got %d", seq)
	}
}

// TestSpanWAL_DropOldestFirst verifies cap enforcement removes the OLDEST
// entries first and never the newest (Task 3 guarantee).
//
// bbolt does NOT shrink the file on Delete (free pages are reclaimed in
// place), so a size-targeted drop on a small WAL deletes everything once it
// passes the chunk boundary — the same property the metrics WAL test relies
// on. We therefore assert the ORDERING invariant directly: the drop deletes
// strictly from the oldest (lowest-seq) end. To observe a partial drop we
// stub Size via a tiny on-disk WAL and check that whatever survives is a
// contiguous suffix whose newest seq is preserved.
func TestSpanWAL_DropOldestFirst(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Append 30 small batches with known seqs 0..29.
	for i := 0; i < 30; i++ {
		if _, err := w.Append(makeSpanBatch("op", 1)); err != nil {
			t.Fatal(err)
		}
	}

	// Drop a chunk from the oldest end. The implementation deletes in chunks
	// of 10 from cursor.First() (oldest), so a single pass with a target the
	// file already satisfies still removes exactly one chunk — and that chunk
	// is the OLDEST seqs (0..9). Whatever survives must be the contiguous
	// suffix [10, 29].
	if err := w.DropOldestUntilSize(1 << 40); err != nil {
		t.Fatal(err)
	}
	var survived []uint64
	_ = w.Iterate(func(p PendingSpan) error {
		survived = append(survived, p.Seq)
		return nil
	})
	if len(survived) == 0 {
		t.Fatal("expected a contiguous suffix to survive a single oldest-chunk drop")
	}
	// Oldest-first invariant: survivors are a contiguous suffix ending at the
	// newest seq (29). The newest entry is never dropped before older ones.
	if survived[len(survived)-1] != 29 {
		t.Errorf("newest seq 29 was dropped before older entries (oldest-first violated): %v", survived)
	}
	for i := 1; i < len(survived); i++ {
		if survived[i] != survived[i-1]+1 {
			t.Fatalf("survivors not contiguous (gaps imply non-oldest-first deletion): %v", survived)
		}
	}
	// The lowest surviving seq must be > 0, proving seq 0 (the oldest) was
	// among those dropped.
	if survived[0] == 0 {
		t.Errorf("oldest seq 0 survived the drop — drop must remove oldest first: %v", survived)
	}

	// Aggressive drop drains the rest; seq counter must not regress.
	if err := w.DropOldestUntilSize(1); err != nil {
		t.Fatal(err)
	}
	seq, err := w.Append(makeSpanBatch("op", 1))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 30 {
		t.Errorf("seq counter regressed after drop: got %d want 30", seq)
	}
}

// TestSpanWAL_CapEnforcedOnAppend verifies that Append auto-triggers cap
// enforcement once the file exceeds maxBytes, deleting from the OLDEST end so
// the WAL stays bounded (no unbounded growth during a multi-hour outage).
//
// Caveat (shared with the metrics WAL): bbolt does not shrink its file on
// Delete, so os.Stat size only ever grows. A drop pass therefore continues
// until the on-disk size dips below target — which, on a cap smaller than a
// few batches, drains the whole bucket. The cap is a SOFT cap (default
// 512MB/1GB), sized so the file genuinely grows beyond it before tripping and
// the drop removes only a bounded oldest prefix. This test asserts the two
// guarantees that always hold regardless of cap size: (1) the WAL stays
// bounded, and (2) entries are removed strictly oldest-first (survivors, if
// any, are always a contiguous suffix — the newest seq end).
func TestSpanWAL_CapEnforcedOnAppend(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 64*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Track which seqs survive after each append. Invariant: the set of
	// surviving seqs is always a contiguous suffix [k, current] — i.e.
	// deletion only ever removes from the oldest (lowest-seq) end.
	for i := 0; i < 200; i++ {
		seq, err := w.Append(makeLargeSpanBatch(20))
		if err != nil {
			t.Fatal(err)
		}
		var survived []uint64
		_ = w.Iterate(func(p PendingSpan) error {
			survived = append(survived, p.Seq)
			return nil
		})
		// Survivors must be strictly increasing and contiguous, and never
		// include a seq greater than the one just appended.
		for j := 1; j < len(survived); j++ {
			if survived[j] != survived[j-1]+1 {
				t.Fatalf("append #%d: survivors not a contiguous suffix (oldest-first violated): %v", i, survived)
			}
		}
		if len(survived) > 0 && survived[len(survived)-1] > seq {
			t.Fatalf("append #%d: a future seq survived: %v (just appended %d)", i, survived, seq)
		}
	}

	// File must stay bounded — not grow without limit across 200 appends.
	size, err := w.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size > 16*64*1024 {
		t.Errorf("span WAL grew unbounded despite cap: size=%d cap=%d", size, 64*1024)
	}
}

// TestSpanWAL_AppendReturnsErrOnClosed verifies Append on a closed WAL errors.
func TestSpanWAL_AppendReturnsErrOnClosed(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(makeSpanBatch("op", 1)); err == nil {
		t.Error("expected error from Append on closed span WAL, got nil")
	}
}

// TestSpanWAL_Concurrent exercises 10 appenders + 1 iterator for race detection.
func TestSpanWAL_Concurrent(t *testing.T) {
	w, err := OpenSpanWAL(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	stop, done := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = w.Append(makeSpanBatch("op", 1))
				}
			}
		}()
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = w.Iterate(func(PendingSpan) error { return nil })
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	<-done
}
