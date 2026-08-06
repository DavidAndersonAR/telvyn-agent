// Package selfmetrics emits metrics about the agent's OWN host on a fixed
// cadence, independent of the scheduler / checks.Runtime / Reload pipeline.
//
// Why a separate path: the scheduler/checksRuntime are server-driven (Reload
// pushes the operator's CheckConfig list). Self-metrics must keep flowing
// regardless of what the operator configures — including when no CheckConfig
// at all is pushed yet (cold start, before first Register response).
//
// Identification: every metric emitted here carries tag {@code __self__=true}.
// The Quarkus VmRemoteWriter intercepts that tag and:
//  1. prefixes __name__ with `agent_host_metric_`
//  2. replaces host_id label with collector_id
//  3. strips __self__ from the label set
//
// This gives operators a way to monitor the collector itself (CPU pressure,
// memory leaks, swap thrashing) without mixing those series into the host
// timeseries the collector polls remotely.
//
// Implementation reuses the existing linux.system Check factory — same code
// path that fires for operator-configured Local Agent mode, but with a
// synthetic CheckConfig flagged as self.
package selfmetrics

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ispwatch/collector/internal/agentstate"
	"github.com/ispwatch/collector/internal/checks"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// SelfTag is the tag key that signals "this metric describes the host where
// the agent runs". Must match the constant the Quarkus VmRemoteWriter looks
// for (see VmRemoteWriter.SELF_TAG_KEY).
const SelfTag = "__self__"

// DefaultInterval is the cadence used when caller passes 0. 30s mirrors the
// Intervalo padrão das métricas internas de saúde do agent.
const DefaultInterval = 30 * time.Second

// Start launches a goroutine that, every `interval`, runs a linux.system
// Check and pushes the resulting metrics — flagged as self — through `out`.
// The goroutine exits when ctx is cancelled.
//
// `collectorID` is informational only; the actual collector_id label is
// resolved server-side from the mTLS cert CN (T-02-02-01 mitigation pattern).
// Logging it here helps correlate "which collector started self-metrics" with
// gRPC server logs.
func Start(
	ctx context.Context,
	log *slog.Logger,
	out chan<- []*collectorv1.Metric,
	collectorID string,
	interval time.Duration,
) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	clog := log.With("component", "selfmetrics", "collector", collectorID)

	// linux.system — CPU/mem/disk/net/load aggregates do host inteiro.
	if !startSelfCheck(ctx, clog, "linux.system", interval, out) {
		return
	}
	// linux.processes — CPU/mem por unit systemd / container (coroot-style).
	// Roda em cadência maior porque cgroup walk é mais caro que /proc/stat.
	startSelfCheck(ctx, clog, "linux.processes", interval*2, out)
}

// startSelfCheck obtém a factory do registry e dispara o ticker. Retorna false
// só quando o check não está sequer registrado (caso patológico — todo binário
// importa internal/checks transitivamente).
func startSelfCheck(
	ctx context.Context,
	clog *slog.Logger,
	checkType string,
	interval time.Duration,
	out chan<- []*collectorv1.Metric,
) bool {
	factory, ok := checks.Default.Get(checkType)
	if !ok {
		clog.Warn("self-check factory missing", "check", checkType)
		return false
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "agent.self." + checkType,
		CheckType: checkType,
		HostId:    "self", // ignored server-side when __self__=true
		Enabled:   true,
		Interval:  durationpb.New(interval),
		StaticTags: map[string]string{
			SelfTag: "true",
		},
	}
	chk, err := factory(cfg)
	if err != nil {
		clog.Warn("self-check factory error", "check", checkType, "err", err)
		return false
	}
	go run(ctx, clog.With("check", checkType), chk, out, interval)
	clog.Info("self-check started", "check", checkType, "interval", interval)
	return true
}

func run(
	ctx context.Context,
	log *slog.Logger,
	chk checks.Check,
	out chan<- []*collectorv1.Metric,
	interval time.Duration,
) {
	runOnce := func() {
		metrics, err := chk.Run(ctx)
		if err != nil {
			log.Debug("self-metrics run error", "err", err)
			return
		}
		if len(metrics) == 0 {
			return
		}
		select {
		case out <- metrics:
		default:
			log.Warn("self-metrics out channel full, dropping batch", "count", len(metrics))
		}

		// Quando o agent foi amarrado a um noc_host (via param
		// local_host_id), duplica cada métrica sem __self__ e com host_id
		// setado ao bigint do host. VmRemoteWriter, sem ver __self__, deixa
		// o nome (cpu_user, mem_used, …) e usa host_id direto — caem nos
		// gráficos da categoria Sistema do noc_host.
		hostID := agentstate.LocalHostID()
		if hostID > 0 {
			hostIDStr := fmt.Sprintf("%d", hostID)
			mirrored := make([]*collectorv1.Metric, 0, len(metrics))
			for _, m := range metrics {
				clone := proto.Clone(m).(*collectorv1.Metric)
				clone.HostId = hostIDStr
				if clone.Tags != nil {
					newTags := make(map[string]string, len(clone.Tags))
					for k, v := range clone.Tags {
						if k == SelfTag {
							continue
						}
						newTags[k] = v
					}
					clone.Tags = newTags
				}
				mirrored = append(mirrored, clone)
			}
			select {
			case out <- mirrored:
			default:
				log.Warn("self-metrics mirror channel full, dropping", "count", len(mirrored))
			}
		}
	}

	// Once-at-start so the dashboard sees CPU baseline immediately. The very
	// first cpu.* delta won't be emitted (linux.system needs 2 samples) — that
	// catch-up happens at the second tick.
	runOnce()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("self-metrics stopped")
			return
		case <-t.C:
			runOnce()
		}
	}
}
