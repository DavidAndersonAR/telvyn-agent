// linux_processes.go — per-service CPU/memory metrics, the way coroot does.
//
// Walks /proc, groups PIDs by cgroup (systemd unit, docker/cri container,
// standalone process), and reads cumulative CPU + RSS from the cgroup
// controller files. Delta CPU between samples is converted to cores-percent
// (100% = 1 core fully used).
//
// Metrics emitted (host-style, with __self__ when invoked by selfmetrics):
//   - service.cpu_pct{service, kind}         (% of 1 core, summed across PIDs in the cgroup)
//   - service.mem_rss_bytes{service, kind}   (anon + mapped_file from memory.stat)
//   - service.proc_count{service, kind}      (number of PIDs in the cgroup)
//
// Service name resolution:
//   - SystemdService cgroup → unit name without ".service" suffix (postgresql, redis-server)
//   - Docker / containerd / crio → "<runtime>:<short-id>" (docker:abc123def456)
//   - Standalone (no service/container) → skipped (would explode cardinality with
//     ephemeral CLIs; doesn't fit the "service" model)
//
// Top-N cap (default 32) keeps the cardinality tractable — fewer than that on
// a typical host, but rare runaway systems can have hundreds of units.
package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dockercontainer "github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ispwatch/collector/internal/ebpf/cgroup"
	"github.com/ispwatch/collector/internal/svcagg"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const defaultProcTopN = 32

type linuxProcessesCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string

	topN int

	mu           sync.Mutex
	lastCpuUsage map[string]float64 // cgroup Id → cumulative cpu seconds
	lastSampleAt time.Time

	// Docker container ID → friendly name cache
	dockerNames     map[string]string
	dockerNamesAt   time.Time
}

func newLinuxProcessesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "linux.processes-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	return &linuxProcessesCheck{
		id:           id,
		interval:     interval,
		hostID:       cfg.GetHostId(),
		staticTags:   tags,
		topN:         defaultProcTopN,
		lastCpuUsage: make(map[string]float64),
	}, nil
}

func (c *linuxProcessesCheck) ID() string              { return c.id }
func (c *linuxProcessesCheck) Interval() time.Duration { return c.interval }
func (c *linuxProcessesCheck) Tags() map[string]string { return c.staticTags }

func (c *linuxProcessesCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	// 1. Group PIDs by cgroup. Cheaper than 1 read per PID for stats because
	// many PIDs share a cgroup (systemd service forks workers, docker container
	// has multiple threads, etc.).
	cgroups, err := scanProcsByCgroup()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.refreshDockerNames()

	now := time.Now()
	var elapsed float64
	if !c.lastSampleAt.IsZero() {
		elapsed = now.Sub(c.lastSampleAt).Seconds()
	}

	// Snapshot dos counters L7-bytes (svcagg). PIDs vivos vão ser usados pra
	// somar bytes por cgroup; PIDs mortos vão ser prunados ao final.
	netSnap := svcagg.Snapshot()
	alivePids := make(map[uint32]struct{}, 256)
	for _, ci := range cgroups {
		for _, pid := range ci.pids {
			alivePids[pid] = struct{}{}
		}
	}

	type sample struct {
		service     string
		kind        string
		cpuPct      float64
		rssBytes    uint64
		procCount   int
		ioReadBytes uint64 // cumulative cgroup disk reads (sum across devices)
		ioWriteBytes uint64
		netRxBytes  uint64 // cumulative L7 payload bytes recebidos (sum dos PIDs do cgroup)
		netTxBytes  uint64
	}
	samples := make([]sample, 0, len(cgroups))
	seenIDs := make(map[string]struct{}, len(cgroups))

	for cgID, ci := range cgroups {
		seenIDs[cgID] = struct{}{}
		name, ok := c.serviceNameFromCgroup(ci.cg)
		if !ok {
			continue // standalone / unknown — skip
		}
		// CPU% — only emitted on 2nd+ sample, when we have a delta baseline.
		var cpuPct float64
		if cpu := ci.cg.CpuStat(); cpu != nil {
			if prev, ok := c.lastCpuUsage[cgID]; ok && elapsed > 0 {
				delta := cpu.UsageSeconds - prev
				if delta > 0 {
					cpuPct = (delta / elapsed) * 100.0
				}
			}
			c.lastCpuUsage[cgID] = cpu.UsageSeconds
		}
		var rss uint64
		if mem := ci.cg.MemoryStat(); mem != nil {
			rss = mem.RSS
		}
		// Cgroup disk I/O — soma read/write bytes através de todos os devices
		// (loop, sda, nvme, etc.). Reportado cumulativo desde a criação do
		// cgroup; o backend vai aplicar rate() pra mostrar bytes/segundo.
		var ioR, ioW uint64
		for _, io := range ci.cg.IOStat() {
			ioR += io.ReadBytes
			ioW += io.WrittenBytes
		}
		// Net bytes — soma os counters svcagg dos PIDs desse cgroup. Idem
		// cumulativo; rate() no backend.
		var netRx, netTx uint64
		for _, pid := range ci.pids {
			if cnt, ok := netSnap[pid]; ok {
				netRx += cnt.NetRx
				netTx += cnt.NetTx
			}
		}
		// Skip cgroups que parecem totalmente idle no PRIMEIRO tick — sem
		// CPU delta ainda, sem RSS, sem IO/net. Tipicamente cgroups stopped
		// que ainda têm o dir mas zero atividade. A partir do 2º tick, sempre
		// emitimos pra manter as séries vivas (zero é um valor válido).
		if cpuPct == 0 && rss == 0 && ioR == 0 && ioW == 0 && netRx == 0 && netTx == 0 && c.lastSampleAt.IsZero() {
			continue
		}
		samples = append(samples, sample{
			service:      name,
			kind:         ci.cg.ContainerType.String(),
			cpuPct:       cpuPct,
			rssBytes:     rss,
			procCount:    len(ci.pids),
			ioReadBytes:  ioR,
			ioWriteBytes: ioW,
			netRxBytes:   netRx,
			netTxBytes:   netTx,
		})
	}

	// Prune lastCpuUsage entries whose cgroup vanished — bounds the cache.
	for id := range c.lastCpuUsage {
		if _, ok := seenIDs[id]; !ok {
			delete(c.lastCpuUsage, id)
		}
	}
	// Same hygiene for svcagg: PIDs que sumiram acumulam memória pra sempre.
	svcagg.PruneDead(alivePids)
	c.lastSampleAt = now

	// Top-N by max(cpu%, rss-normalized).  RSS divided by an arbitrary
	// constant just to keep ranking sane vs cpu%; not exact, but stable.
	sort.Slice(samples, func(i, j int) bool {
		ai := samples[i].cpuPct + float64(samples[i].rssBytes)/(1<<30)
		aj := samples[j].cpuPct + float64(samples[j].rssBytes)/(1<<30)
		if ai != aj {
			return ai > aj
		}
		return samples[i].service < samples[j].service
	})
	if c.topN > 0 && len(samples) > c.topN {
		samples = samples[:c.topN]
	}

	// Emit — 7 séries por serviço (cpu, mem, proc_count, io_read/write, net_rx/tx).
	ts := timestamppb.New(now)
	out := make([]*collectorv1.Metric, 0, len(samples)*7)
	for _, s := range samples {
		tags := map[string]string{
			"service": s.service,
			"kind":    s.kind,
		}
		out = append(out, c.metric(ts, "service.cpu_pct", s.cpuPct, tags))
		out = append(out, c.metric(ts, "service.mem_rss_bytes", float64(s.rssBytes), tags))
		out = append(out, c.metric(ts, "service.proc_count", float64(s.procCount), tags))
		out = append(out, c.metric(ts, "service.io_read_bytes", float64(s.ioReadBytes), tags))
		out = append(out, c.metric(ts, "service.io_write_bytes", float64(s.ioWriteBytes), tags))
		out = append(out, c.metric(ts, "service.net_rx_bytes", float64(s.netRxBytes), tags))
		out = append(out, c.metric(ts, "service.net_tx_bytes", float64(s.netTxBytes), tags))
	}
	return out, nil
}

func (c *linuxProcessesCheck) metric(ts *timestamppb.Timestamp, name string, val float64, extra map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+len(extra))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	for k, v := range extra {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       ts,
		HostId:     c.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "linux.processes",
	}
}

// cgInfo holds a parsed cgroup + the list of PIDs that resolved to it.
// Manter os PIDs (não só o count) deixa o sum de svcagg per-service ser
// trivial: pra cada cgroup, somo os counters de todos os PIDs dela.
type cgInfo struct {
	cg   *cgroup.Cgroup
	pids []uint32
}

// scanProcsByCgroup walks /proc/<pid>/cgroup for every numeric PID dir and
// groups them by cgroup Id. Errors on individual PIDs (already-exited
// processes between readdir and open) are silently skipped — they would
// just flap the counts otherwise.
func scanProcsByCgroup() (map[string]*cgInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan /proc: %w", err)
	}
	out := make(map[string]*cgInfo, 64)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only numeric dirnames are PIDs.
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		cg, err := cgroup.NewFromProcessCgroupFile(filepath.Join("/proc", e.Name(), "cgroup"))
		if err != nil {
			// Most common: PID exited mid-scan, file is gone. Don't log.
			continue
		}
		if cg == nil || cg.Id == "" {
			continue
		}
		info, ok := out[cg.Id]
		if !ok {
			info = &cgInfo{cg: cg}
			out[cg.Id] = info
		}
		info.pids = append(info.pids, pid)
	}
	return out, nil
}

// refreshDockerNames queries the Docker API for running containers and
// caches container ID prefix → friendly name (compose service or container name).
// Called at most once per minute to avoid hammering the daemon.
func (c *linuxProcessesCheck) refreshDockerNames() {
	if c.dockerNames != nil && time.Since(c.dockerNamesAt) < time.Minute {
		return
	}
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		if c.dockerNames == nil {
			c.dockerNames = map[string]string{}
		}
		return
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	containers, err := cli.ContainerList(ctx, dockercontainer.ListOptions{})
	if err != nil {
		if c.dockerNames == nil {
			c.dockerNames = map[string]string{}
		}
		return
	}
	m := make(map[string]string, len(containers))
	for _, ct := range containers {
		name := ""
		if v := ct.Labels["com.docker.compose.service"]; v != "" {
			name = v
		} else if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}
		if name == "" {
			continue
		}
		name = strings.ToLower(name)
		// Index by full ID and 12-char prefix
		m[ct.ID] = name
		if len(ct.ID) >= 12 {
			m[ct.ID[:12]] = name
		}
	}
	c.dockerNames = m
	c.dockerNamesAt = time.Now()
}

// resolveDockerName returns the friendly name for a container ID, or empty string.
func (c *linuxProcessesCheck) resolveDockerName(containerId string) string {
	if c.dockerNames == nil {
		return ""
	}
	if name, ok := c.dockerNames[containerId]; ok {
		return name
	}
	if len(containerId) >= 12 {
		if name, ok := c.dockerNames[containerId[:12]]; ok {
			return name
		}
	}
	return ""
}

// serviceNameFromCgroup turns a parsed cgroup into a human service name.
// Returns ok=false for cgroups that don't represent a "service" worth a row
// in the UI (root cgroup, ephemeral standalone processes, user sessions).
func (c *linuxProcessesCheck) serviceNameFromCgroup(cg *cgroup.Cgroup) (string, bool) {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		name := cg.ContainerId
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		name = strings.TrimSuffix(name, ".service")
		if name == "" {
			return "", false
		}
		return name, true
	case cgroup.ContainerTypeDocker:
		if friendly := c.resolveDockerName(cg.ContainerId); friendly != "" {
			return friendly, true
		}
		if len(cg.ContainerId) >= 12 {
			return "docker:" + cg.ContainerId[:12], true
		}
		return "docker:" + cg.ContainerId, cg.ContainerId != ""
	case cgroup.ContainerTypeContainerd:
		if len(cg.ContainerId) >= 12 {
			return "containerd:" + cg.ContainerId[:12], true
		}
		return "containerd:" + cg.ContainerId, cg.ContainerId != ""
	case cgroup.ContainerTypeCrio:
		if len(cg.ContainerId) >= 12 {
			return "crio:" + cg.ContainerId[:12], true
		}
		return "crio:" + cg.ContainerId, cg.ContainerId != ""
	case cgroup.ContainerTypeLxc:
		if cg.ContainerId == "" {
			return "", false
		}
		return "lxc:" + cg.ContainerId, true
	default:
		// Standalone processes, root cgroups, user.slice/* — skip. They're
		// covered by host-level cpu_user/mem_used aggregates.
		return "", false
	}
}

// init auto-registers the linux.processes factory in the Default registry.
func init() {
	Default.Register("linux.processes", newLinuxProcessesCheck)
}
