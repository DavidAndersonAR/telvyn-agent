package sendbuf

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Falha de rede retém; flush posterior reenvia na ordem.
func TestRetainAndFlush(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("a"), errors.New("connection refused"))
	q.Offer([]byte("b"), errors.New("connection refused"))

	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 || sent[0] != "a" || sent[1] != "b" {
		t.Fatalf("esperava reenvio [a b] em ordem, veio %v", sent)
	}
	// fila vazia depois do flush
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		t.Fatal("fila deveria estar vazia")
		return nil
	})
}

// Estourou o teto de bytes → descarta o mais antigo, nunca cresce sem limite.
func TestDropOldestOnOverflow(t *testing.T) {
	q := New("test", 10, nil) // teto de 10 bytes
	q.Offer([]byte("11111"), errors.New("net"))
	q.Offer([]byte("22222"), errors.New("net"))
	q.Offer([]byte("33333"), errors.New("net")) // 15 bytes → dropa "11111"

	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 || sent[0] != "22222" || sent[1] != "33333" {
		t.Fatalf("esperava [22222 33333], veio %v", sent)
	}
}

// 401 é terminal: descarta (não retém) e ativa o cool-down.
func TestAuthFailureDropsAndBlocks(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("x"), fmt.Errorf("ingest traces: %w", &StatusError{Code: 401}))
	if !q.Blocked() {
		t.Fatal("401 deveria ativar o cool-down")
	}
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		t.Fatal("payload de 401 não deveria ter sido retido")
		return nil
	})
}

// 429 (franquia) também é terminal e bloqueia.
func TestBudgetFailureBlocks(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("x"), &StatusError{Code: 429})
	if !q.Blocked() {
		t.Fatal("429 deveria ativar o cool-down")
	}
}

// Falha no meio do flush: item que falhou por REDE continua retido.
func TestFlushStopsOnNetworkError(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("a"), errors.New("net"))
	q.Offer([]byte("b"), errors.New("net"))

	calls := 0
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		calls++
		return errors.New("still down")
	})
	if calls != 1 {
		t.Fatalf("flush deveria parar na 1ª falha, tentou %d", calls)
	}
	// os 2 itens seguem retidos
	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 {
		t.Fatalf("esperava 2 retidos, veio %d", len(sent))
	}
}
