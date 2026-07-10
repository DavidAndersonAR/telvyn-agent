// logs_test.go — testes do LogsExporter (buffer/flush/overflow).
//
// Cobrem os dois comportamentos que resolvem o "logs buffer overflow" visto em
// homolog:
//   - flush por tamanho: um batch cheio drena ANTES do ticker de 2s (sem isso,
//     rajada estoura o buffer à toa esperando o próximo tick);
//   - overflow FIFO: acima do teto dropa só o excedente e conta em droppedTotal.

package otlp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestLogsExporter sobe um servidor HTTP efêmero e devolve um LogsExporter
// (modo mTLS/endpoint, mas sobre HTTP plano do httptest) apontado pra ele.
// onBatch recebe o corpo de cada POST.
func newTestLogsExporter(t *testing.T, onBatch func(body []byte)) *LogsExporter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		onBatch(b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	e, err := NewLogsExporter(srv.URL, "tenant", "collector", "", "", "", quietLogger())
	if err != nil {
		t.Fatalf("NewLogsExporter: %v", err)
	}
	return e
}

// countRecords conta os records no corpo logBatchWire.
func countRecords(body []byte) int {
	var w struct {
		Records []json.RawMessage `json:"records"`
	}
	_ = json.Unmarshal(body, &w)
	return len(w.Records)
}

// TestLogsSizeTriggeredFlush prova que um batch cheio drena bem antes do ticker
// de 2s — ou seja, o gatilho por tamanho (flushSignal) está ativo.
func TestLogsSizeTriggeredFlush(t *testing.T) {
	got := make(chan int, 8)
	e := newTestLogsExporter(t, func(body []byte) { got <- countRecords(body) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	for i := 0; i < LogsBatchMaxRecords; i++ {
		e.Push(LogRecord{Body: "linha", ServiceName: "svc"})
	}

	// Discriminador: 1s é muito abaixo do LogsBatchFlushInterval (2s), então
	// receber nesse prazo só pode ter vindo do flush por tamanho.
	const deadline = time.Second
	if LogsBatchFlushInterval <= deadline {
		t.Fatalf("teste inválido: flush interval (%v) precisa ser > deadline (%v)", LogsBatchFlushInterval, deadline)
	}
	select {
	case n := <-got:
		if n != LogsBatchMaxRecords {
			t.Fatalf("batch com %d records, esperava %d", n, LogsBatchMaxRecords)
		}
	case <-time.After(deadline):
		t.Fatalf("flush por tamanho não disparou em %v (só o ticker de %v drenaria)", deadline, LogsBatchFlushInterval)
	}
}

// TestLogsBufferOverflowDropsOldest prova que acima do teto o buffer dropa só o
// excedente (FIFO) e contabiliza em droppedTotal. Não roda o Run: o buffer deve
// encher sem drenar.
func TestLogsBufferOverflowDropsOldest(t *testing.T) {
	e := newTestLogsExporter(t, func([]byte) {})

	const extra = 50
	for i := 0; i < LogsBufferMaxRecords+extra; i++ {
		e.Push(LogRecord{Body: "x"})
	}

	st := e.Stats()
	if st.LinesTotal != int64(LogsBufferMaxRecords+extra) {
		t.Fatalf("LinesTotal=%d, esperava %d", st.LinesTotal, LogsBufferMaxRecords+extra)
	}
	if st.DroppedTotal != int64(extra) {
		t.Fatalf("DroppedTotal=%d, esperava %d (dropa só o excedente do teto)", st.DroppedTotal, extra)
	}
}
