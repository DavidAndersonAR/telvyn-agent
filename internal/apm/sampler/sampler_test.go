package sampler

import (
	"fmt"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func sp(traceID string, status int32, durNano int64) *collectorv1.Span {
	return &collectorv1.Span{
		TraceId:       traceID,
		StatusCode:    status,
		StartUnixNano: 1_000,
		EndUnixNano:   1_000 + durNano,
	}
}

func TestSampler_ErroESlowSempreMantidos(t *testing.T) {
	s := New(0, 100*time.Millisecond) // baseRate 0 → normais descartados
	if !s.Keep(sp("t1", 2, 1)) {
		t.Error("erro deveria ser sempre mantido")
	}
	if !s.Keep(sp("t2", 1, int64(200*time.Millisecond))) {
		t.Error("lento deveria ser sempre mantido")
	}
	if s.Keep(sp("t3", 1, 1)) {
		t.Error("normal rápido com baseRate 0 deveria ser descartado")
	}
}

func TestSampler_Determinismo(t *testing.T) {
	s := New(0.5, 0)
	first := s.Keep(sp("trace-abc", 1, 1))
	for i := 0; i < 100; i++ {
		if s.Keep(sp("trace-abc", 1, 1)) != first {
			t.Fatal("decisão deve ser determinística pro mesmo trace_id")
		}
	}
}

func TestSampler_TaxaAproximada(t *testing.T) {
	s := New(0.10, 0)
	kept := 0
	const n = 20000
	for i := 0; i < n; i++ {
		if s.Keep(sp(fmt.Sprintf("trace-%d", i), 1, 1)) {
			kept++
		}
	}
	rate := float64(kept) / float64(n)
	if rate < 0.08 || rate > 0.12 { // ~10% com folga
		t.Fatalf("taxa de amostragem fora do esperado: %.3f (kept=%d)", rate, kept)
	}
}

func TestSampler_Extremos(t *testing.T) {
	if New(1, 0).Keep(sp("x", 1, 1)) != true {
		t.Error("baseRate 1 mantém tudo")
	}
	if New(0, 0).Keep(sp("x", 1, 1)) != false {
		t.Error("baseRate 0 descarta normais")
	}
	if New(0.5, 0).Keep(nil) != false {
		t.Error("nil não é mantido")
	}
}
