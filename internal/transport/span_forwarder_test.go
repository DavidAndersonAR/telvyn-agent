package transport

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/transport/wal"
)

// openTestSpanWAL opens a span WAL in a temp directory with no cap.
func openTestSpanWAL(t *testing.T) *wal.SpanWAL {
	t.Helper()
	w, err := wal.OpenSpanWAL(filepath.Join(t.TempDir(), "spans.db"), 0)
	if err != nil {
		t.Fatalf("open span wal: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func makeTestSpanBatch(n int) *collectorv1.SpanBatch {
	b := &collectorv1.SpanBatch{CollectorId: "col-01"}
	for i := 0; i < n; i++ {
		b.Spans = append(b.Spans, &collectorv1.Span{TraceId: "t", SpanId: "s", Name: "op"})
	}
	return b
}

// TestSpanProducer_AppendsToWAL verifies a batch fed through Run lands in the
// span WAL before any sender consumes it (append-before-send durability).
func TestSpanProducer_AppendsToWAL(t *testing.T) {
	w := openTestSpanWAL(t)
	p := NewSpanProducer(w, testLogger(t))

	in := make(chan *collectorv1.SpanBatch, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, in)

	in <- makeTestSpanBatch(3)

	// Notify must fire after the WAL append.
	select {
	case <-p.Notify():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected notify after span append")
	}

	count := 0
	_ = w.Iterate(func(_ wal.PendingSpan) error { count++; return nil })
	if count != 1 {
		t.Errorf("expected 1 span WAL entry, got %d", count)
	}
}

// TestSpanProducer_SkipsEmptyBatch verifies a nil/empty batch is ignored (no
// WAL entry, no notify).
func TestSpanProducer_SkipsEmptyBatch(t *testing.T) {
	w := openTestSpanWAL(t)
	p := NewSpanProducer(w, testLogger(t))

	in := make(chan *collectorv1.SpanBatch, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, in)

	in <- &collectorv1.SpanBatch{CollectorId: "col-01"} // no spans
	in <- nil

	select {
	case <-p.Notify():
		t.Error("unexpected notify for empty/nil batch")
	case <-time.After(80 * time.Millisecond):
		// OK
	}
	count := 0
	_ = w.Iterate(func(_ wal.PendingSpan) error { count++; return nil })
	if count != 0 {
		t.Errorf("expected 0 span WAL entries for empty batches, got %d", count)
	}
}

// TestSpanProducer_StampsBatchSeq verifies the producer stamps the WAL seq
// onto the persisted batch so the replay path can correlate acks.
func TestSpanProducer_StampsBatchSeq(t *testing.T) {
	w := openTestSpanWAL(t)
	p := NewSpanProducer(w, testLogger(t))

	in := make(chan *collectorv1.SpanBatch, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, in)

	in <- makeTestSpanBatch(1)
	in <- makeTestSpanBatch(1)

	// Drain both notifies (level-triggered, may coalesce).
	time.Sleep(100 * time.Millisecond)

	var seqs []uint64
	_ = w.Iterate(func(pp wal.PendingSpan) error {
		seqs = append(seqs, pp.Seq)
		return nil
	})
	if len(seqs) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(seqs))
	}
	if seqs[0] != 0 || seqs[1] != 1 {
		t.Errorf("expected seqs [0 1], got %v", seqs)
	}
}
