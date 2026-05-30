package transport

import (
	"context"
	"fmt"
	"log/slog"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// StreamEvents opens the bidirectional StreamEvents RPC and drains a channel
// of event batches into it. Mirror minimalista do streamMetricsLegacy (sem
// WAL) — events sao melhor-esforço e baixo-volume (autodescoberta dispara em
// rajadas curtas), entao perda em reconnect e aceitavel.
//
// Acks sao logados mas nao re-enfileirados. Reconnect loop em RunForever
// reabre a stream apos qualquer erro; novos eventos vindos do canal entram
// na proxima sessao.
//
// Returns the error that broke the stream (nil on clean ctx cancellation) so
// the RunForever reconnect loop can decide whether to back off.
func (c *Conn) StreamEvents(ctx context.Context, log *slog.Logger, in <-chan []*collectorv1.Event) error {
	stream, err := c.client.StreamEvents(ctx)
	if err != nil {
		return fmt.Errorf("open StreamEvents: %w", err)
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
				log.Warn("event batch rejected by server",
					"batch_seq", ack.GetBatchSeq(),
					"rejected", ack.GetRejected(),
					"error", ack.GetError(),
				)
				continue
			}
			log.Debug("event ack",
				"batch_seq", ack.GetBatchSeq(),
				"accepted", ack.GetAccepted(),
			)
		}
	}()

	var seq int64
	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-recvErr:
			return fmt.Errorf("event stream recv: %w", err)
		case events, ok := <-in:
			if !ok {
				_ = stream.CloseSend()
				return nil
			}
			if len(events) == 0 {
				continue
			}
			seq++
			batch := &collectorv1.EventBatch{
				CollectorId: c.collector,
				BatchSeq:    seq,
				Events:      events,
			}
			if err := stream.Send(batch); err != nil {
				return fmt.Errorf("event stream send: %w", err)
			}
			log.Debug("event batch sent", "batch_seq", seq, "count", len(events))
		}
	}
}
