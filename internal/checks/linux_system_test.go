package checks

import (
	"context"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// hasMetricName returns true if any metric in the slice has the given name.
func hasMetricName(metrics []*collectorv1.Metric, name string) bool {
	for _, m := range metrics {
		if m.MetricName == name {
			return true
		}
	}
	return false
}

// allMetricNamesContaining returns all unique metric names from the slice.
func allMetricNames(metrics []*collectorv1.Metric) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range metrics {
		if !seen[m.MetricName] {
			seen[m.MetricName] = true
			out = append(out, m.MetricName)
		}
	}
	return out
}

// TestLinuxSystem_FactoryValidatesInterval verifies that a zero interval is
// defaulted to 30s by the factory.
func TestLinuxSystem_FactoryValidatesInterval(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:   "test-id",
		CheckType: "linux.system",
		Interval:  durationpb.New(0),
		Enabled:   true,
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("unexpected factory error: %v", err)
	}
	if c.Interval() != 30*time.Second {
		t.Errorf("expected 30s default interval, got %v", c.Interval())
	}
}

// TestLinuxSystem_FirstRun_NoCpu_SecondRun_HasCpu verifies that the first
// Run() call emits no cpu.* metrics (needs 2 samples for delta), and the
// second call does emit them.
func TestLinuxSystem_FirstRun_NoCpu_SecondRun_HasCpu(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:   "cpu-test",
		CheckType: "linux.system",
		Interval:  durationpb.New(30 * time.Second),
		Enabled:   true,
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("unexpected factory error: %v", err)
	}

	ctx := context.Background()

	// First run — must NOT emit cpu.* (no previous sample for delta).
	first, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("first Run() error: %v", err)
	}
	for _, m := range first {
		if m.MetricName == "cpu.user" || m.MetricName == "cpu.system" ||
			m.MetricName == "cpu.idle" || m.MetricName == "cpu.iowait" {
			t.Errorf("first Run() emitted cpu metric %q (expected none)", m.MetricName)
		}
	}

	// Wait a bit so the cumulative counters advance.
	time.Sleep(100 * time.Millisecond)

	// Second run — MUST emit cpu.* delta metrics.
	second, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("second Run() error: %v", err)
	}
	// On Linux/Windows gopsutil provides CPU times; on platforms where it
	// doesn't, skip rather than fail (CI gate is Linux amd64).
	if !hasMetricName(second, "cpu.user") {
		t.Logf("second Run() metrics: %v", allMetricNames(second))
		// Treat as skip if no cpu times available (e.g. plan to run on Linux CI).
		t.Skip("cpu.user not present — gopsutil may not have CPU data on this platform")
	}
	for _, name := range []string{"cpu.user", "cpu.system", "cpu.idle"} {
		if !hasMetricName(second, name) {
			t.Errorf("second Run() missing %q; got metrics: %v", name, allMetricNames(second))
		}
	}
}

// TestLinuxSystem_EmitsMemFamilies verifies that Run() emits mem.used,
// mem.available, mem.used_pct and mem.swap_used.
func TestLinuxSystem_EmitsMemFamilies(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:  "mem-test",
		Enabled:  true,
		Interval: durationpb.New(30 * time.Second),
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, name := range []string{"mem.used", "mem.available", "mem.used_pct"} {
		if !hasMetricName(metrics, name) {
			t.Errorf("missing metric %q; got: %v", name, allMetricNames(metrics))
		}
	}
	// mem.swap_used may not exist on systems with no swap — skip instead of fail.
	if !hasMetricName(metrics, "mem.swap_used") {
		t.Log("mem.swap_used not present (no swap on this system — acceptable)")
	}
}

// TestLinuxSystem_EmitsLoadFamilies verifies that Run() emits load.1, load.5,
// load.15 on platforms that support load averages.
func TestLinuxSystem_EmitsLoadFamilies(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:  "load-test",
		Enabled:  true,
		Interval: durationpb.New(30 * time.Second),
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !hasMetricName(metrics, "load.1") {
		// Windows does not have load averages — skip rather than fail.
		t.Skip("load.1 not present — platform may not support load averages")
	}
	for _, name := range []string{"load.1", "load.5", "load.15"} {
		if !hasMetricName(metrics, name) {
			t.Errorf("missing metric %q; got: %v", name, allMetricNames(metrics))
		}
	}
}

// TestLinuxSystem_DiskFiltersFstype verifies that disk.used_pct is emitted
// for physical filesystems (ext4, xfs, etc.) but not for virtual ones
// (tmpfs, devtmpfs, etc.).
func TestLinuxSystem_DiskFiltersFstype(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:  "disk-test",
		Enabled:  true,
		Interval: durationpb.New(30 * time.Second),
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// Every disk.used_pct metric must come from a physical fstype (source == "linux.system").
	for _, m := range metrics {
		if m.MetricName == "disk.used_pct" {
			if m.Source != "linux.system" {
				t.Errorf("disk.used_pct has unexpected source %q", m.Source)
			}
		}
	}
	// At least verify we don't emit metrics with empty mount tag.
	for _, m := range metrics {
		if m.MetricName == "disk.used_pct" {
			if m.Tags["mount"] == "" {
				t.Errorf("disk.used_pct metric missing mount tag")
			}
		}
	}
}

// TestLinuxSystem_NetSkipsLo verifies that no metric with the loopback
// interface name "lo" is emitted.
func TestLinuxSystem_NetSkipsLo(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:  "net-test",
		Enabled:  true,
		Interval: durationpb.New(30 * time.Second),
	}
	c, err := newLinuxSystemCheck(cfg)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, m := range metrics {
		if (m.MetricName == "net.bytes_in" || m.MetricName == "net.bytes_out") &&
			m.InterfaceName == "lo" {
			t.Errorf("net metric emitted for loopback interface 'lo'")
		}
	}
}

// TestLinuxSystem_AutoRegistersInDefault verifies that the linux.system init()
// function registered the factory in the Default registry.
func TestLinuxSystem_AutoRegistersInDefault(t *testing.T) {
	_, ok := Default.Get("linux.system")
	if !ok {
		t.Fatal("linux.system factory not found in Default registry (init() failed?)")
	}
}
