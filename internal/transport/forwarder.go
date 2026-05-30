// Package transport — forwarder.go implements the Producer side of the
// Producer→WAL→Sender pipeline (Plan 5, D-06 always-on).
//
// Data flow:
//
//	checks.Runtime out chan  ──┐
//	scheduler.Runtime out chan ─┤ FanIn ──► Producer.Push ──► WAL.Append ──► notify
//	adapters out chan          ─┘                                                │
//	                                                                             ▼
//	                                                                      Sender (stream.go)
//
// The Producer aggregates individual []*Metric slices into MetricBatch values
// (up to batchSize metrics per batch, or flushed on flushInterval, whichever
// comes first) and persists each batch to the WAL BEFORE the sender goroutine
// is notified. This guarantees at-least-once delivery even if the sender
// crashes between Append and Send.
package transport

import (
	"context"
	"log/slog"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/transport/wal"
)

// Producer aggregates Metric slices from upstream channels into MetricBatch
// values and persists each batch to the WAL before signalling the sender.
//
// Backpressure: if WAL.Append fails (e.g. disk full), the batch is dropped
// with a Warn log. This is intentional — the alternative (blocking) would
// stall the checks.Runtime goroutines indefinitely.
type Producer struct {
	w             *wal.WAL
	collectorID   string
	log           *slog.Logger
	batchSize     int
	flushInterval time.Duration

	mu      sync.Mutex
	pending []*collectorv1.Metric
	notify  chan struct{}
}

// NewProducer creates a Producer. batchSize<=0 defaults to 500; flush<=0
// defaults to 1 second. Both match the Quarkus VmRemoteWriter throughput
// assumptions from Plan 2.
func NewProducer(w *wal.WAL, collectorID string, log *slog.Logger, batchSize int, flush time.Duration) *Producer {
	if batchSize <= 0 {
		batchSize = 500
	}
	if flush <= 0 {
		flush = time.Second
	}
	return &Producer{
		w:             w,
		collectorID:   collectorID,
		log:           log,
		batchSize:     batchSize,
		flushInterval: flush,
		notify:        make(chan struct{}, 1),
	}
}

// Push appends metrics to the in-memory aggregation buffer. When the buffer
// reaches batchSize it triggers an immediate Flush; otherwise the ticker in
// RunFlushLoop handles periodic flushing.
func (p *Producer) Push(metrics []*collectorv1.Metric) {
	if len(metrics) == 0 {
		return
	}
	p.mu.Lock()
	p.pending = append(p.pending, metrics...)
	full := len(p.pending) >= p.batchSize
	p.mu.Unlock()
	if full {
		p.Flush()
	}
}

// Flush drains the pending buffer into a MetricBatch and persists it to the
// WAL. No-op when the buffer is empty. Safe to call concurrently — the
// internal mutex serialises access to pending.
func (p *Producer) Flush() {
	p.mu.Lock()
	if len(p.pending) == 0 {
		p.mu.Unlock()
		return
	}
	batch := &collectorv1.MetricBatch{
		CollectorId: p.collectorID,
		Metrics:     p.pending,
	}
	p.pending = nil
	p.mu.Unlock()

	seq, err := p.w.Append(batch)
	if err != nil {
		p.log.Warn("forwarder: WAL append failed, dropping batch",
			"count", len(batch.Metrics),
			"err", err,
		)
		return
	}
	// Store seq in batch so the sender can use it as MetricBatch.BatchSeq.
	// (Batch is already in WAL; this in-memory mutation does not affect
	// durability — the sender reads from WAL on Iterate/replay.)
	batch.BatchSeq = int64(seq)

	// Non-blocking signal to the sender goroutine: at least one new entry
	// is ready. If the channel already has a pending signal the sender will
	// pick it up soon; we don't block here.
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// RunFlushLoop ticks at flushInterval until ctx is done. On cancellation it
// performs a final Flush to drain any buffered metrics before exit.
func (p *Producer) RunFlushLoop(ctx context.Context) {
	t := time.NewTicker(p.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Flush()
			return
		case <-t.C:
			p.Flush()
		}
	}
}

// Notify returns the channel the sender goroutine consumes to learn about new
// WAL appends. The sender should call WAL.Iterate after receiving a signal to
// drain all pending entries (not just one — the signal is level-triggered by
// design: one signal may cover N appends).
func (p *Producer) Notify() <-chan struct{} { return p.notify }

// FanIn merges N upstream metric channels into Producer.Push. Each source
// gets its own goroutine so a slow source cannot block faster ones.
// All goroutines exit when ctx is done or their source channel is closed.
func (p *Producer) FanIn(ctx context.Context, sources ...<-chan []*collectorv1.Metric) {
	for _, src := range sources {
		src := src
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case metrics, ok := <-src:
					if !ok {
						return
					}
					p.Push(metrics)
				}
			}
		}()
	}
}
