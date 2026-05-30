package transport

import (
	"context"
	"fmt"
	"log/slog"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/transport/wal"
)

// StreamMetrics opens the bidirectional StreamMetrics RPC and drives
// at-least-once delivery via the WAL (Plan 5, D-06 always-on).
//
// On entry (and after every reconnect by the RunForever caller) it replays
// all unacked WAL entries oldest-first so no metrics are lost across
// disconnects (gate D-10).
//
// Acks:
//   - MetricAck.rejected == 0 and MetricAck.error == "" → WAL.Ack(seq) deletes
//     the entry (at-most-once-send per reconnect session, at-least-once overall).
//   - MetricAck.rejected > 0 or MetricAck.error != "" → log Warn, keep entry in
//     WAL so the next replay re-sends it. Server-side rejection is treated as a
//     soft error; the entry will be retried after reconnect.
//
// Returns the error that broke the stream (nil on clean ctx cancellation) so
// the RunForever reconnect loop can decide whether to back off.
func (c *Conn) StreamMetrics(ctx context.Context, log *slog.Logger, w *wal.WAL, notify <-chan struct{}) error {
	stream, err := c.client.StreamMetrics(ctx)
	if err != nil {
		return fmt.Errorf("open StreamMetrics: %w", err)
	}

	// recvErr carries the first error from the ack-receiver goroutine.
	recvErr := make(chan error, 1)
	go func() {
		for {
			ack, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if ack.GetRejected() > 0 || ack.GetError() != "" {
				// Server rejected the batch or returned an error.
				// Keep in WAL — next replay will resend.
				log.Warn("server rejected batch — keeping in WAL for resend",
					"batch_seq", ack.GetBatchSeq(),
					"rejected", ack.GetRejected(),
					"error", ack.GetError(),
				)
				continue
			}
			// Ack OK — remove from WAL. Idempotent on missing key.
			if err := w.Ack(uint64(ack.GetBatchSeq())); err != nil {
				log.Warn("wal ack failed", "seq", ack.GetBatchSeq(), "err", err)
			} else {
				log.Debug("ack",
					"batch_seq", ack.GetBatchSeq(),
					"accepted", ack.GetAccepted(),
				)
			}
		}
	}()

	// replay sends all pending WAL entries (oldest first) on the current
	// stream. Called on startup and on every notify signal.
	replay := func() error {
		return w.Iterate(func(p wal.Pending) error {
			// Use WAL seq as BatchSeq — Ack handler maps ack.batch_seq → wal seq
			// directly (Opção A from plan). CollectorId is stamped by the sender
			// (this function) so it carries the live conn's collector identity.
			batch := p.Batch
			batch.CollectorId = c.collector
			batch.BatchSeq = int64(p.Seq)
			if err := stream.Send(batch); err != nil {
				return fmt.Errorf("send seq=%d: %w", p.Seq, err)
			}
			return nil
		})
	}

	// Initial replay: drain everything left from a previous run or previous
	// connection (gate D-10 — disconnect > 256 batches without loss).
	if err := replay(); err != nil {
		_ = stream.CloseSend()
		return fmt.Errorf("initial replay: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-recvErr:
			return fmt.Errorf("stream recv: %w", err)
		case <-notify:
			// At least one new batch was appended to the WAL. Replay all
			// pending entries — this covers both the new append and any
			// previously un-acked entries from rejected batches.
			if err := replay(); err != nil {
				_ = stream.CloseSend()
				return fmt.Errorf("notified replay: %w", err)
			}
		}
	}
}

// streamMetricsLegacy is the old in-channel based implementation kept here
// for reference only. It is no longer called — RunForever now uses the WAL
// variant above. Will be removed in a cleanup plan.
//
// Deprecated: use StreamMetrics(ctx, log, wal, notify) instead.
func (c *Conn) streamMetricsLegacy(ctx context.Context, log *slog.Logger, in <-chan []*collectorv1.Metric) error {
	stream, err := c.client.StreamMetrics(ctx)
	if err != nil {
		return fmt.Errorf("open StreamMetrics: %w", err)
	}
	recvErr := make(chan error, 1)
	go func() {
		for {
			ack, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if ack.GetRejected() > 0 {
				log.Warn("server rejected metrics",
					"batch_seq", ack.GetBatchSeq(),
					"rejected", ack.GetRejected(),
					"error", ack.GetError(),
				)
			} else {
				log.Debug("ack",
					"batch_seq", ack.GetBatchSeq(),
					"accepted", ack.GetAccepted(),
				)
			}
		}
	}()
	var seq int64
	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-recvErr:
			return fmt.Errorf("stream recv: %w", err)
		case metrics, ok := <-in:
			if !ok {
				_ = stream.CloseSend()
				return nil
			}
			if len(metrics) == 0 {
				continue
			}
			seq++
			batch := &collectorv1.MetricBatch{
				CollectorId: c.collector,
				BatchSeq:    seq,
				Metrics:     metrics,
			}
			if err := stream.Send(batch); err != nil {
				return fmt.Errorf("stream send: %w", err)
			}
		}
	}
}
