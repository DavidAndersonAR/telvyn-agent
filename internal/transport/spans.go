package transport

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ispwatch/collector/internal/transport/wal"
)

// StreamSpans opens the bidirectional StreamSpans RPC and drives at-least-once
// delivery of traces via the span WAL (Task 1, trace durability). It mirrors
// StreamMetrics exactly:
//
// On entry (and after every reconnect by the RunForever caller) it replays
// all unacked span WAL entries oldest-first so no spans are lost across
// disconnects, backend restarts, or multi-hour POP isolation.
//
// Acks:
//   - SpanAck.rejected == 0 and SpanAck.error == "" → SpanWAL.Ack(seq) deletes
//     the entry.
//   - SpanAck.rejected > 0 or SpanAck.error != "" → log Warn, keep entry in
//     WAL so the next replay re-sends it.
//
// Returns the error that broke the stream (nil on clean ctx cancellation).
func (c *Conn) StreamSpans(ctx context.Context, log *slog.Logger, w *wal.SpanWAL, notify <-chan struct{}) error {
	stream, err := c.client.StreamSpans(ctx)
	if err != nil {
		return fmt.Errorf("open StreamSpans: %w", err)
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			ack, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if ack.GetRejected() > 0 || ack.GetError() != "" {
				// Keep in WAL — next replay will resend.
				log.Warn("span batch rejected by server — keeping in WAL for resend",
					"batch_seq", ack.GetBatchSeq(),
					"rejected", ack.GetRejected(),
					"error", ack.GetError(),
				)
				continue
			}
			if err := w.Ack(uint64(ack.GetBatchSeq())); err != nil {
				log.Warn("span wal ack failed", "seq", ack.GetBatchSeq(), "err", err)
			} else {
				log.Debug("span ack",
					"batch_seq", ack.GetBatchSeq(),
					"accepted", ack.GetAccepted(),
				)
			}
		}
	}()

	// replay sends all pending span WAL entries (oldest first) on the current
	// stream. Called on startup and on every notify signal.
	replay := func() error {
		return w.Iterate(func(p wal.PendingSpan) error {
			batch := p.Batch
			batch.CollectorId = c.collector
			batch.BatchSeq = int64(p.Seq)
			if err := stream.Send(batch); err != nil {
				return fmt.Errorf("span send seq=%d: %w", p.Seq, err)
			}
			return nil
		})
	}

	// Initial replay: drain everything left from a previous run or connection.
	if err := replay(); err != nil {
		_ = stream.CloseSend()
		return fmt.Errorf("initial span replay: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-recvErr:
			return fmt.Errorf("span stream recv: %w", err)
		case <-notify:
			// At least one new batch was appended to the WAL. Replay all
			// pending entries (covers the new append + any previously
			// un-acked entries from rejected batches).
			if err := replay(); err != nil {
				_ = stream.CloseSend()
				return fmt.Errorf("notified span replay: %w", err)
			}
		}
	}
}
