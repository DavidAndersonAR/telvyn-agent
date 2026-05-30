// forwarder.go — buffer + flush loop que pega spans recebidos pelo
// Receiver e envia em batches via channel pro transport (que abre
// StreamSpans com o backend).
//
// Reusa o mesmo gRPC client/cert mTLS dos outros streams (metrics, events).
// Aqui só agregamos + empacotamos; transport.StreamSpans drena o channel.
//
// Sem WAL: tracing é nice-to-have e métricas são críticas — não queremos
// que tracing concorra pelo orçamento de disco do WAL nesta versão.
// Backpressure: se o channel está cheio, dropamos do buffer (FIFO) ao invés
// de bloquear o receiver — preferimos perder spans antigos a derrubar a
// app instrumentada.

package otlp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Forwarder agrega spans recebidos via Push, faz flush periódico em
// SpanBatch e empurra pro channel out (drenado pelo transport).
type Forwarder struct {
	collectorID string
	maxBatch    int
	interval    time.Duration
	log         *slog.Logger

	out chan<- *collectorv1.SpanBatch

	mu      sync.Mutex
	buf     []*collectorv1.Span
	dropped int64
	seq     int64
}

func NewForwarder(collectorID string, log *slog.Logger, out chan<- *collectorv1.SpanBatch, maxBatch int, interval time.Duration) *Forwarder {
	if maxBatch <= 0 {
		maxBatch = 500
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Forwarder{
		collectorID: collectorID,
		maxBatch:    maxBatch,
		interval:    interval,
		log:         log.With("component", "otlp-forwarder"),
		out:         out,
	}
}

// Push é o handler do SpanSink — adiciona ao buffer. Se buffer estoura
// MaxBatch * 4, dropa do começo (FIFO) — proteção contra OOM se backend
// ficar offline por muito tempo.
func (f *Forwarder) Push(spans []*collectorv1.Span) {
	if len(spans) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, spans...)
	if cap := f.maxBatch * 4; len(f.buf) > cap {
		drop := len(f.buf) - cap
		f.buf = f.buf[drop:]
		f.dropped += int64(drop)
		f.log.Warn("span buffer overflow, dropped oldest", "dropped", drop, "buffered", len(f.buf))
	}
}

// Run flush loop. Drena buffer no intervalo configurado.
func (f *Forwarder) Run(ctx context.Context) {
	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			f.flush(ctx) // best-effort
			return
		case <-ticker.C:
			f.flush(ctx)
		}
	}
}

func (f *Forwarder) flush(ctx context.Context) {
	f.mu.Lock()
	if len(f.buf) == 0 {
		f.mu.Unlock()
		return
	}
	n := len(f.buf)
	if n > f.maxBatch {
		n = f.maxBatch
	}
	batch := f.buf[:n]
	f.buf = f.buf[n:]
	f.seq++
	seq := f.seq
	f.mu.Unlock()

	out := &collectorv1.SpanBatch{
		CollectorId: f.collectorID,
		BatchSeq:    seq,
		Spans:       batch,
	}
	select {
	case f.out <- out:
		f.log.Debug("span batch enqueued", "seq", seq, "count", len(batch))
	case <-ctx.Done():
	default:
		// channel cheio — transport está atrasado ou desconectado.
		// Dropa este batch (preferimos perda silenciosa a blocking).
		f.mu.Lock()
		f.dropped += int64(len(batch))
		f.mu.Unlock()
		f.log.Warn("span out channel full, batch dropped", "seq", seq, "count", len(batch))
	}
}

// Stats devolve contadores cumulativos (chamado pelo selfmetrics).
func (f *Forwarder) Stats() (buffered, dropped int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.buf)), f.dropped
}
