package main

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/ispwatch/collector/internal/ebpf"
	"github.com/ispwatch/collector/internal/ebpf/cpuprofiler"
	"github.com/ispwatch/collector/internal/otlp"
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
// S2: o emit ENVIA cada janela pro gateway (POST /api/ingest/v1/profile,
// source=ebpf) reusando o PostRaw do exporter. Só manda janelas atribuídas a um
// POD k8s (namespace+pod resolvidos) — processos de host e threads de kernel
// (kworker, containerd, k3s-server…) ficam de fora pra não virar "serviço" no
// catálogo; a visão do nó inteiro é uma fatia posterior (S4).
func startEbpfProfiler(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, resolver *ebpf.PodResolverImpl) {
	plog := log.With("component", "cpuprofiler")
	emit := func(ctx context.Context, windows []cpuprofiler.Window) {
		sent, failed, skipped := 0, 0, 0
		for _, w := range windows {
			if w.Namespace == "" || w.Pod == "" {
				skipped++ // host/kernel — sem pod resolvido (node view é S4)
				continue
			}
			body, err := json.Marshal(map[string]any{
				"service":              w.Service,
				"namespace":            w.Namespace,
				"pod":                  w.Pod,
				"profile_type":         w.ProfileType,
				"source":               w.Source,
				"window_start_unix_ms": w.WindowStartMs,
				"window_seconds":       w.WindowSeconds,
				"period_ms":            w.PeriodMs,
				"folded":               w.Folded,
			})
			if err != nil {
				failed++
				continue
			}
			if err := exporter.PostRaw(ctx, "profile", "application/json", body); err != nil {
				failed++
				if failed == 1 { // não inunda o log: 1 aviso por janela de flush
					plog.Warn("envio de profile falhou", "service", w.Service, "pod", w.Pod, "err", err)
				}
				continue
			}
			sent++
		}
		plog.Info("profiles eBPF enviados", "windows", len(windows), "sent", sent, "skipped_host", skipped, "failed", failed)
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
