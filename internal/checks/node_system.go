// node_system.go — coletor de CPU/mem/load do NÓ (a máquina física) no modo
// k8s, lido DIRETO de /host/proc e reportado sob o host_id do nó.
//
// Por quê: no modo k8s o agente só coleta o kubelet (que dá USO — nanocores,
// working_set — mas não capacidade), então a tela Servidores mostrava CPU/mem
// em cores/bytes em vez de %. O Datadog resolve isso lendo o /proc do nó. Aqui
// lemos /host/proc (já montado pelo DaemonSet) e emitimos as três métricas que o
// endpoint /machines usa pra %: cpu.idle, mem.used_pct, load.5 — mais cpu.usage
// (= 100 - idle%), o nome canônico compartilhado com os perfis SNMP, pra um único
// monitor de CPU cobrir equipamento de rede, servidor Linux e nó k8s.
//
// Não usa gopsutil de propósito: o gopsutil aponta o host-path por env/context
// global, o que contaminaria o self-metrics do agente (que precisa ler o /proc
// do PRÓPRIO container). Ler os arquivos direto é determinístico e isolado.
package checks

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// StartNodeSystem dispara, em goroutine, um coletor que a cada `interval` lê
// `procRoot` (ex.: /host/proc) e empurra cpu.idle/cpu.usage/mem.used_pct/load.5
// sob `hostID` no canal `out`. CPU é delta entre amostras: o 1º tick só guarda a
// baseline (emite mem+load), o cpu sai a partir do 2º. Sai quando ctx cancela.
func StartNodeSystem(
	ctx context.Context,
	log *slog.Logger,
	out chan<- []*collectorv1.Metric,
	hostID string,
	procRoot string,
	interval time.Duration,
) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	clog := log.With("component", "node-system", "host_id", hostID, "proc", procRoot)

	var lastIdle, lastTotal float64
	var haveCPU bool

	emit := func() {
		now := timestamppb.Now()
		var ms []*collectorv1.Metric

		if idle, total, ok := readCPU(procRoot); ok {
			if haveCPU && total > lastTotal {
				pct := (idle - lastIdle) / (total - lastTotal) * 100
				ms = append(ms, nodeMetric(now, hostID, "cpu.idle", pct))
				// cpu.usage — mesmo nome CANÔNICO que os perfis SNMP publicam, pra UM
				// único monitor "CPU acima de X%" cobrir equipamento de rede, servidor
				// Linux e nó k8s. O /machines segue usando cpu.idle (não mexemos nele).
				ms = append(ms, nodeMetric(now, hostID, "cpu.usage", 100-pct))
			}
			lastIdle, lastTotal, haveCPU = idle, total, true
		}
		if pct, ok := readMemUsedPct(procRoot); ok {
			ms = append(ms, nodeMetric(now, hostID, "mem.used_pct", pct))
		}
		if l5, ok := readLoad5(procRoot); ok {
			ms = append(ms, nodeMetric(now, hostID, "load.5", l5))
		}
		if len(ms) == 0 {
			return
		}
		select {
		case out <- ms:
		default:
			clog.Warn("node-system out channel full, dropping batch", "count", len(ms))
		}
	}

	go func() {
		emit() // baseline (sem cpu.idle ainda)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				clog.Info("node-system stopped")
				return
			case <-t.C:
				emit()
			}
		}
	}()
	clog.Info("node-system started (host /proc → cpu%/mem%)", "interval", interval)
}

func nodeMetric(t *timestamppb.Timestamp, hostID, name string, val float64) *collectorv1.Metric {
	return &collectorv1.Metric{
		Time:       t,
		HostId:     hostID,
		MetricName: name,
		Value:      val,
		Source:     "linux.system",
	}
}

// readCPU lê a linha agregada "cpu ..." de <procRoot>/stat e devolve
// (idle_jiffies, total_jiffies). idle = campo idle (índice 4); total = soma de
// todos os campos. O usage% no backend é 100 - cpu.idle%.
func readCPU(procRoot string) (idle, total float64, ok bool) {
	f, err := os.Open(procRoot + "/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text()) // ["cpu", user, nice, system, idle, iowait, ...]
	if len(fields) < 6 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i := 1; i < len(fields); i++ {
		v, perr := strconv.ParseFloat(fields[i], 64)
		if perr != nil {
			continue
		}
		total += v
		if i == 4 { // idle
			idle = v
		}
	}
	if total <= 0 {
		return 0, 0, false
	}
	return idle, total, true
}

// readMemUsedPct lê MemTotal e MemAvailable de <procRoot>/meminfo e devolve
// (Total-Available)/Total*100 — mesma conta do UsedPercent do gopsutil.
func readMemUsedPct(procRoot string) (float64, bool) {
	f, err := os.Open(procRoot + "/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	var total, avail float64
	var haveT, haveA bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			total, haveT = meminfoKB(line), true
		} else if strings.HasPrefix(line, "MemAvailable:") {
			avail, haveA = meminfoKB(line), true
		}
		if haveT && haveA {
			break
		}
	}
	if !haveT || !haveA || total <= 0 {
		return 0, false
	}
	return (total - avail) / total * 100, true
}

func meminfoKB(line string) float64 {
	fs := strings.Fields(line) // ["MemTotal:", "16384000", "kB"]
	if len(fs) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[1], 64)
	return v
}

// readLoad5 lê o 2º campo (load de 5 min) de <procRoot>/loadavg.
func readLoad5(procRoot string) (float64, bool) {
	b, err := os.ReadFile(procRoot + "/loadavg")
	if err != nil {
		return 0, false
	}
	fs := strings.Fields(string(b)) // ["0.10", "0.20", "0.30", "1/234", "5678"]
	if len(fs) < 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fs[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
