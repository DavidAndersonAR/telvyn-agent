package ebpf

import (
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/ebpf/l7"
)

// physicalL7Latency é o guard que barra o dado de latência corrompido do kernel
// (underflow de end-start em conexão long-lived) que envenenava o DDSketch e
// fazia o p95 do postgres virar "25 dias".
func TestPhysicalL7Latency(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		ok   bool
	}{
		{"negativa (underflow do u64)", -18 * 24 * time.Hour, false},
		{"zero", 0, false},
		{"25 dias (inflada)", 25 * 24 * time.Hour, false},
		{"logo acima do teto", maxL7Latency + time.Second, false},
		{"exatamente no teto", maxL7Latency, true},
		{"1ms normal", time.Millisecond, true},
		{"500ms normal", 500 * time.Millisecond, true},
		{"1ns", time.Nanosecond, true},
	}
	for _, tc := range cases {
		if got := physicalL7Latency(tc.d); got != tc.ok {
			t.Errorf("%s: physicalL7Latency(%v)=%v, quer %v", tc.name, tc.d, got, tc.ok)
		}
	}
}

// buildSpan deve DESCARTAR (nil) um evento L7 com latência não-física, antes de
// tocar em parser/conn — o guard fica logo após o check de r==nil.
func TestBuildSpanDropsCorruptedLatency(t *testing.T) {
	for _, d := range []time.Duration{-time.Hour, 0, 25 * 24 * time.Hour} {
		ev := Event{Type: EventTypeL7Request, L7Request: &l7.RequestData{Duration: d}}
		if span := buildSpan(ev, nil, nil, BridgeConfig{}); span != nil {
			t.Fatalf("latência %v devia ser descartada, veio span", d)
		}
	}
}
