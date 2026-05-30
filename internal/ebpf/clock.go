// Conversão de timestamp eBPF (CLOCK_MONOTONIC, via bpf_ktime_get_ns) pra
// Unix wall-clock nanos. Sem essa conversão, spans saem com start_unix_nano
// igual ao uptime do host (= "1970-01-01 + N segundos de boot"), quebrando
// qualquer filtro de janela temporal no backend.
package ebpf

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	monoOffsetOnce sync.Once
	monoOffsetNs   int64
)

// MonoToWallNs converte um timestamp monotonic (bpf_ktime_get_ns) em
// Unix-epoch nanoseconds. Calcula o offset uma única vez por processo —
// drift do clock dentro do uptime do agent é desprezível pra spans (<1ms).
//
// Aceita também timestamps que já vêm wall-clock (ex: init.go usa
// time.Now().UnixNano() pra carimbar conexões pré-existentes). Threshold:
// 1.5e18 ns ≈ ano 2017 — qualquer valor acima disso já é wall-clock.
// Monotonic uptime de um host real raramente passa de ~1e17 ns (3 anos).
func MonoToWallNs(ts uint64) int64 {
	if ts > wallClockThresholdNs {
		return int64(ts)
	}
	monoOffsetOnce.Do(initMonoOffset)
	return int64(ts) + monoOffsetNs
}

const wallClockThresholdNs uint64 = 1_500_000_000_000_000_000

func initMonoOffset() {
	var ts unix.Timespec
	// CLOCK_MONOTONIC casa com o que bpf_ktime_get_ns() retorna (em kernels
	// modernos). bpf_ktime_get_boot_ns() inclui suspend; só relevante em
	// laptops/edge — nossos hosts são servers/VMs sem suspend.
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fallback: sem offset, mantém o comportamento bugado mas explícito.
		monoOffsetNs = 0
		return
	}
	monoNow := ts.Sec*int64(time.Second/time.Nanosecond) + ts.Nsec
	wallNow := time.Now().UnixNano()
	monoOffsetNs = wallNow - monoNow
}
