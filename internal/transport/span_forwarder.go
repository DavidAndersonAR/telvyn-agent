// span_forwarder.go is the Producer side of the span Producer→WAL→Sender
// pipeline, mirroring forwarder.go for metrics (Task 1, trace durability).
//
// Data flow:
//
//	otlp.Forwarder ──► SpanBatch chan ──► SpanProducer.Run ──► SpanWAL.Append ──► notify
//	                                                                                │
//	                                                                                ▼
//	                                                                  Sender (StreamSpans)
//
// The otlp.Forwarder already aggregates raw spans into SpanBatch values; the
// SpanProducer's only job is to persist each batch to the WAL BEFORE the
// sender goroutine is notified. This guarantees at-least-once delivery even
// if the sender crashes or the backend is offline — spans now survive a
// backend restart or a multi-hour POP isolation, same as metrics.
package transport

import (
	"context"
	"log/slog"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/transport/wal"
)

// SpanProducer drains SpanBatch values from the otlp.Forwarder channel and
// persists each one to the span WAL before signalling the sender.
//
// Backpressure: if SpanWAL.Append fails (e.g. disk full), the batch is
// dropped with a Warn log — same policy as the metrics Producer. The
// alternative (blocking) would stall the OTLP receiver path.
type SpanProducer struct {
	w   *wal.SpanWAL
	log *slog.Logger

	notify chan struct{}
}

// NewSpanProducer creates a SpanProducer backed by w.
func NewSpanProducer(w *wal.SpanWAL, log *slog.Logger) *SpanProducer {
	if log == nil {
		log = slog.Default()
	}
	return &SpanProducer{
		w:      w,
		log:    log.With("component", "span-forwarder"),
		notify: make(chan struct{}, 1),
	}
}

// Notify returns the channel the sender goroutine consumes to learn about new
// WAL appends. Level-triggered: one signal may cover N appends, so the sender
// must drain the whole WAL via Iterate after each signal.
func (p *SpanProducer) Notify() <-chan struct{} { return p.notify }

// Run consumes batches from in, appends each to the WAL, and signals the
// sender. Exits when ctx is done or in is closed.
func (p *SpanProducer) Run(ctx context.Context, in <-chan *collectorv1.SpanBatch) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-in:
			if !ok {
				return
			}
			if batch == nil || len(batch.Spans) == 0 {
				continue
			}
			p.append(batch)
		}
	}
}

// append persists one batch and signals the sender (non-blocking).
func (p *SpanProducer) append(batch *collectorv1.SpanBatch) {
	seq, err := p.w.Append(batch)
	if err != nil {
		p.log.Warn("span forwarder: WAL append failed, dropping batch",
			"count", len(batch.Spans),
			"err", err,
		)
		return
	}
	batch.BatchSeq = int64(seq)
	select {
	case p.notify <- struct{}{}:
	default:
	}
}
