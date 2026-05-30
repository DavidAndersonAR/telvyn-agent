// linux_system.go — the "linux.system" Check implementation.
//
// Collects host-level system metrics using gopsutil/v4:
//   - cpu.user / cpu.system / cpu.idle / cpu.iowait   (delta %, first run skipped)
//   - mem.used / mem.available / mem.used_pct          (bytes / %)
//   - mem.swap_used                                     (bytes)
//   - disk.used_pct{mount, device}                     (%, physical fstypes only)
//   - net.bytes_in / net.bytes_out{interface_name}     (cumulative bytes, lo skipped)
//   - load.1 / load.5 / load.15                        (Linux/macOS only)
//
// Metric names match the Quarkus VmRemoteWriter regex ^(cpu|mem|disk|net|load)\.
// so they are forwarded to VictoriaMetrics without being dropped.
//
// Local Agent mode (D-12): the check runs on the same host as the agent —
// it reads /proc/stat, /proc/meminfo, /sys/class/net, etc. via gopsutil.
// No shell commands, no cgo.
package checks

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// physicalFs is the allow-list of filesystem types considered "physical"
// (i.e. backed by real storage). Virtual mounts (tmpfs, devtmpfs, proc,
// sysfs, cgroup, overlay, squashfs, binfmt_misc) are excluded from disk
// metrics to avoid cardinality explosion and misleading usage numbers.
var physicalFs = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true,
	"xfs":      true,
	"btrfs":    true,
	"zfs":      true,
	"reiserfs": true,
	"jfs":      true,
	"apfs":     true,
	"ntfs":     true,
	"fat32":    true,
	"exfat":    true,
}

// linuxSystemCheck is the concrete implementation of Check for linux.system.
type linuxSystemCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string

	// lastCpu holds the previous cpu.TimesWithContext sample. CPU metrics are
	// deltas between consecutive samples, so the first Run() call stores the
	// baseline and emits no cpu.* metrics. Second and later calls compute and
	// emit the delta.
	lastCpu []cpu.TimesStat
}

// newLinuxSystemCheck is the Factory function registered at init() for
// "linux.system". Validates and defaults the CheckConfig fields.
func newLinuxSystemCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "linux.system-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	return &linuxSystemCheck{
		id:         id,
		interval:   interval,
		hostID:     cfg.GetHostId(),
		staticTags: tags,
	}, nil
}

func (c *linuxSystemCheck) ID() string              { return c.id }
func (c *linuxSystemCheck) Interval() time.Duration { return c.interval }
func (c *linuxSystemCheck) Tags() map[string]string { return c.staticTags }

// Run collects one sample and emits all metric families. CPU is delta-based
// (first call only stores baseline, returns no cpu.* metrics).
func (c *linuxSystemCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	now := timestamppb.Now()
	var out []*collectorv1.Metric

	// --- CPU (cumulative seconds → delta %) ---
	// cpu.TimesWithContext(ctx, false) returns aggregate across all cores.
	// Values are cumulative, so we keep the previous sample and calculate delta.
	times, err := cpu.TimesWithContext(ctx, false)
	if err == nil && len(times) > 0 {
		t := times[0]
		if len(c.lastCpu) > 0 {
			prev := c.lastCpu[0]
			// total delta in CPU-seconds (all states combined).
			total := (t.User + t.System + t.Idle + t.Iowait) -
				(prev.User + prev.System + prev.Idle + prev.Iowait)
			if total > 0 {
				out = append(out, c.metric(now, "cpu.user", (t.User-prev.User)/total*100, nil))
				out = append(out, c.metric(now, "cpu.system", (t.System-prev.System)/total*100, nil))
				out = append(out, c.metric(now, "cpu.idle", (t.Idle-prev.Idle)/total*100, nil))
				out = append(out, c.metric(now, "cpu.iowait", (t.Iowait-prev.Iowait)/total*100, nil))
			}
		}
		c.lastCpu = times // always update baseline (even on first call)
	}

	// --- Memory ---
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "mem.used", float64(v.Used), nil))
		out = append(out, c.metric(now, "mem.available", float64(v.Available), nil))
		out = append(out, c.metric(now, "mem.used_pct", v.UsedPercent, nil))
	}
	if s, err := mem.SwapMemoryWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "mem.swap_used", float64(s.Used), nil))
	}

	// --- Disk per mount (physical fstypes only) ---
	parts, _ := disk.PartitionsWithContext(ctx, false)
	for _, p := range parts {
		if !physicalFs[p.Fstype] {
			continue
		}
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			continue
		}
		tags := map[string]string{
			"mount":  p.Mountpoint,
			"device": p.Device,
		}
		out = append(out, c.metric(now, "disk.used_pct", u.UsedPercent, tags))
	}

	// --- Net per interface (skip loopback) ---
	counters, _ := gopsutilnet.IOCountersWithContext(ctx, true)
	for _, n := range counters {
		// Skip loopback on Linux ("lo") and Windows ("Loopback Pseudo-Interface 1").
		if n.Name == "lo" || n.Name == "Loopback Pseudo-Interface 1" {
			continue
		}
		m1 := c.metric(now, "net.bytes_in", float64(n.BytesRecv), nil)
		m1.InterfaceName = n.Name
		m2 := c.metric(now, "net.bytes_out", float64(n.BytesSent), nil)
		m2.InterfaceName = n.Name
		out = append(out, m1, m2)
	}

	// --- Load average (Linux / macOS; Windows returns error — ignored) ---
	if l, err := load.AvgWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "load.1", l.Load1, nil))
		out = append(out, c.metric(now, "load.5", l.Load5, nil))
		out = append(out, c.metric(now, "load.15", l.Load15, nil))
	}

	return out, nil
}

// metric constructs a collectorv1.Metric with the check's static tags merged
// with any extra per-metric tags. Extra tags take precedence.
func (c *linuxSystemCheck) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+len(extraTags))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "linux.system",
	}
}

// init auto-registers the linux.system factory in the Default registry.
// Placing the registration here (rather than in main.go) follows the
// datadog-agent pattern: each check package registers itself, and the
// binary only needs to blank-import the packages it wants.
func init() {
	Default.Register("linux.system", newLinuxSystemCheck)
}
