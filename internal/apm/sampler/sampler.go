// Package sampler decide quais traces guardar em DETALHE (spans crus), igual ao
// trace-agent do Datadog: mantém tudo que é erro, tudo que é lento, e uma
// AMOSTRA determinística dos normais — descarta o resto.
//
// Importante: as ESTATÍSTICAS (concentrator) são contadas ANTES do sampler, com
// 100% dos spans. Então hits/errors/p95 continuam EXATOS mesmo guardando o
// detalhe de só 1 trace em N. O sampler só afeta o que vira waterfall.
//
// A decisão dos "normais" é um hash determinístico do trace_id: o mesmo trace
// recebe sempre a mesma decisão, em qualquer batch ou agent — então um trace é
// mantido ou descartado INTEIRO, sem waterfall quebrado.
package sampler

import (
	"hash/fnv"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Sampler é imutável e seguro pra uso concorrente (sem estado mutável).
type Sampler struct {
	baseRate      float64 // fração [0,1] dos traces normais mantidos
	slowThreshold int64   // nanos; spans >= isso são sempre mantidos (0 = desliga)
}

// New cria um sampler. baseRate é clampado em [0,1].
func New(baseRate float64, slowThreshold time.Duration) *Sampler {
	switch {
	case baseRate < 0:
		baseRate = 0
	case baseRate > 1:
		baseRate = 1
	}
	return &Sampler{baseRate: baseRate, slowThreshold: int64(slowThreshold)}
}

// Keep decide se o span deve ser guardado em detalhe.
func (s *Sampler) Keep(span *collectorv1.Span) bool {
	if span == nil {
		return false
	}
	return s.KeepRaw(span.TraceId, span.StatusCode, span.EndUnixNano-span.StartUnixNano)
}

// KeepRaw é a mesma decisão a partir dos campos crus — usada no caminho OTLP do
// receiver, que lida com tracepb.Span (não com collectorv1.Span).
func (s *Sampler) KeepRaw(traceID string, statusCode int32, durationNano int64) bool {
	// 1) erro — sempre mantém.
	if statusCode == 2 {
		return true
	}
	// 2) lento — sempre mantém.
	if s.slowThreshold > 0 && durationNano >= s.slowThreshold {
		return true
	}
	// 3) amostra determinística dos normais.
	if s.baseRate >= 1 {
		return true
	}
	if s.baseRate <= 0 {
		return false
	}
	threshold := uint64(s.baseRate * float64(^uint64(0)))
	return traceHash(traceID) < threshold
}

func traceHash(traceID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(traceID))
	return h.Sum64()
}
