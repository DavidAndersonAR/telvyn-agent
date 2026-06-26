package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/ispwatch/collector/internal/ebpf"
	"github.com/ispwatch/collector/internal/ebpf/cpuprofiler"
)

// profileResolverAdapter adapta o PodResolverImpl (k8s) à interface do
// cpuprofiler: PID → (service, namespace, pod) com unified service tagging.
// service vazio quando o pod não resolve → o profiler dobra a amostra sob o
// nome do processo (comm).
type profileResolverAdapter struct{ r *ebpf.PodResolverImpl }

func (a profileResolverAdapter) ResolveProfile(pid uint32) (service, namespace, pod string) {
	ns, p, ok := a.r.Resolve(pid)
	if !ok {
		return "", "", ""
	}
	svc, _, _, _ := a.r.ServiceForPod(ns, p)
	return svc, ns, p
}

// startEbpfProfiler sobe o profiler de CPU eBPF em goroutine (best-effort).
// Coleção eBPF SEPARADA do tracer L7: se o verifier rejeitar (kernel sem
// suporte) ou faltar privilégio, só o profiler fica off — o L7 nunca é tocado.
//
// No S1 o emit apenas LOGA o resumo por serviço (prova "amostra + dobra"); o
// envio pro ingest (/api/ingest/v1/profile, source=ebpf) é o S2.
func startEbpfProfiler(ctx context.Context, log *slog.Logger, resolver *ebpf.PodResolverImpl) {
	plog := log.With("component", "cpuprofiler")
	emit := func(_ context.Context, windows []cpuprofiler.Window) {
		for _, w := range windows {
			distinctStacks := strings.Count(w.Folded, "\n")
			plog.Info("janela de profile (S1 print)",
				"service", w.Service, "namespace", w.Namespace, "pod", w.Pod,
				"distinct_stacks", distinctStacks, "window_s", w.WindowSeconds, "period_ms", w.PeriodMs)
			if i := strings.IndexByte(w.Folded, '\n'); i > 0 {
				plog.Debug("folded[0]", "line", w.Folded[:i])
			}
		}
	}
	prof := cpuprofiler.New(cpuprofiler.Config{
		Resolver: profileResolverAdapter{r: resolver},
		Emit:     emit,
	})
	go func() {
		if err := prof.Run(ctx); err != nil {
			plog.Warn("profiler desligado (kernel sem suporte ou sem privilégio)", "err", err)
		}
	}()
}
