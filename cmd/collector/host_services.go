// host_services.go — descoberta de SERVIÇOS locais numa máquina (modo ingest).
//
// Enumera os processos que ESCUTAM porta TCP (via /proc + gopsutil), com CPU e
// memória de cada um, e reporta pelo ingest certless (POST /host/services →
// noc_host_service). É o "processes / service discovery" do Datadog aplicado ao
// host Linux/Docker: a lente de Máquina passa a mostrar "o que roda aqui".
//
// CPU é DELTA: reusamos o *process.Process entre ticks (cache por pid) e
// chamamos Percent(0), que na 2ª chamada em diante devolve o uso desde a última
// medição. O 1º tick de um processo devolve a média desde o start (baseline).
package main

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/ispwatch/collector/internal/otlp"
)

const hostServicesInterval = 60 * time.Second

// hostServicesEnabled — toggle (estilo Datadog). Ligado por padrão no install
// Linux (é a substância da lente); desliga com ISPWATCH_HOST_SERVICES=0.
func hostServicesEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ISPWATCH_HOST_SERVICES")))
	return v != "0" && v != "false" && v != "no" && v != "off"
}

// startHostServicesReport dispara a coleta periódica de serviços do host e o
// envio pelo exporter. Espelho de startLinuxSystemCheck, mas fala direto com o
// exporter (não passa pelo canal de métricas).
func startHostServicesReport(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, hostID string) {
	r := &hostServicesReporter{
		exporter: exporter,
		hostID:   hostID,
		log:      log.With("component", "host-services", "host_id", hostID),
		procs:    map[int32]*process.Process{},
	}
	go func() {
		r.runOnce(ctx)
		t := time.NewTicker(hostServicesInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.runOnce(ctx)
			}
		}
	}()
	r.log.Info("host services discovery started", "interval", hostServicesInterval.String())
}

type hostServicesReporter struct {
	exporter *otlp.IngestExporter
	hostID   string
	log      *slog.Logger
	// procs mantém o *process.Process entre ticks pra o Percent(0) render delta.
	procs map[int32]*process.Process
}

func (r *hostServicesReporter) runOnce(ctx context.Context) {
	services, err := r.collect(ctx)
	if err != nil {
		r.log.Debug("host services collect error", "err", err)
		return
	}
	hid, _ := strconv.Atoi(r.hostID)
	payload := map[string]any{"host_id": hid, "services": services}
	if err := r.exporter.PostHostServices(ctx, payload); err != nil {
		r.log.Warn("host services post falhou", "err", err, "count", len(services))
		return
	}
	r.log.Debug("host services reported", "count", len(services))
}

// collect lista os processos que escutam TCP, agrupando portas por pid, com
// CPU (delta) e RSS de cada processo. Retorna o shape que o backend espera.
func (r *hostServicesReporter) collect(ctx context.Context) ([]map[string]any, error) {
	conns, err := gopsutilnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, err
	}

	portsByPid := map[int32]map[int]bool{}
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Pid <= 0 || c.Laddr.Port == 0 {
			continue
		}
		set := portsByPid[c.Pid]
		if set == nil {
			set = map[int]bool{}
			portsByPid[c.Pid] = set
		}
		set[int(c.Laddr.Port)] = true
	}

	nextProcs := make(map[int32]*process.Process, len(portsByPid))
	out := make([]map[string]any, 0, len(portsByPid))
	for pid, portSet := range portsByPid {
		p := r.procs[pid] // reusa pra o delta de CPU
		if p == nil {
			p, err = process.NewProcessWithContext(ctx, pid)
			if err != nil || p == nil {
				continue
			}
		}
		name, err := p.NameWithContext(ctx)
		if err != nil || strings.TrimSpace(name) == "" {
			continue
		}
		nextProcs[pid] = p

		cmdline := ""
		if cl, e := p.CmdlineWithContext(ctx); e == nil {
			cmdline = cl
			if len(cmdline) > 500 {
				cmdline = cmdline[:500]
			}
		}
		var cpuPct float64
		if v, e := p.PercentWithContext(ctx, 0); e == nil {
			cpuPct = round1(v)
		}
		var memBytes uint64
		if mi, e := p.MemoryInfoWithContext(ctx); e == nil && mi != nil {
			memBytes = mi.RSS
		}

		ports := make([]int, 0, len(portSet))
		for port := range portSet {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		portObjs := make([]map[string]any, 0, len(ports))
		for _, port := range ports {
			portObjs = append(portObjs, map[string]any{"port": port, "proto": "tcp"})
		}

		out = append(out, map[string]any{
			"process":   name,
			"pid":       int(pid),
			"cmdline":   cmdline,
			"cpu_pct":   cpuPct,
			"mem_bytes": memBytes,
			"ports":     portObjs,
		})
	}
	r.procs = nextProcs // poda pids mortos
	return out, nil
}

// round1 arredonda pra 1 casa (evita ruído de float no % de CPU).
func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
