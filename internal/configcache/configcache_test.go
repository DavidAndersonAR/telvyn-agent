package configcache

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func cfgWithChecks(n int) *collectorv1.CollectorConfig {
	c := &collectorv1.CollectorConfig{}
	for i := 0; i < n; i++ {
		c.Checks = append(c.Checks, &collectorv1.CheckConfig{
			CheckId:   "chk",
			CheckType: "linux.system",
			Enabled:   true,
			Interval:  durationpb.New(30_000_000_000),
		})
	}
	return c
}

func cfgWithJobs(n int) *collectorv1.CollectorConfig {
	c := &collectorv1.CollectorConfig{}
	for i := 0; i < n; i++ {
		c.ScheduledJobs = append(c.ScheduledJobs, &collectorv1.ScheduledJob{
			JobId: "j", Tool: "snmp.get", IntervalSeconds: 30, HostId: "h", Enabled: true,
		})
	}
	return c
}

func cfgWithAdapters(n int) *collectorv1.CollectorConfig {
	c := &collectorv1.CollectorConfig{}
	for i := 0; i < n; i++ {
		c.Adapters = append(c.Adapters, &collectorv1.AdapterConfig{Kind: "zabbix"})
	}
	return c
}

// TestIsNonEmpty is the table that drives the keep-current-on-empty decision.
func TestIsNonEmpty(t *testing.T) {
	cases := []struct {
		name string
		cfg  *collectorv1.CollectorConfig
		want bool
	}{
		{"nil", nil, false},
		{"empty", &collectorv1.CollectorConfig{}, false},
		{"only batch knobs (no jobs)", &collectorv1.CollectorConfig{MetricBatchSize: 500, HeartbeatSeconds: 30}, false},
		{"has check", cfgWithChecks(1), true},
		{"has job", cfgWithJobs(1), true},
		{"has adapter", cfgWithAdapters(1), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsNonEmpty(c.cfg); got != c.want {
				t.Errorf("IsNonEmpty(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestSaveLoadRoundTrip verifies a non-empty config persists and reloads with
// its job-defining content intact (cached config loads on startup).
func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-cache.pb")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	orig := cfgWithChecks(2)
	orig.ScheduledJobs = cfgWithJobs(1).ScheduledJobs
	orig.Adapters = cfgWithAdapters(1).Adapters

	if err := c.Save(orig); err != nil {
		t.Fatal(err)
	}

	// Fresh Cache instance (simulates a restart) loads the same content.
	c2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected cached config, got nil")
	}
	if len(got.GetChecks()) != 2 {
		t.Errorf("checks: got %d want 2", len(got.GetChecks()))
	}
	if len(got.GetScheduledJobs()) != 1 {
		t.Errorf("jobs: got %d want 1", len(got.GetScheduledJobs()))
	}
	if len(got.GetAdapters()) != 1 {
		t.Errorf("adapters: got %d want 1", len(got.GetAdapters()))
	}
}

// TestSaveEmptyIsNoOp verifies an empty config does NOT clobber a previously
// cached good config (keep-current-on-empty at the persistence layer).
func TestSaveEmptyIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-cache.pb")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	// Persist a good config.
	if err := c.Save(cfgWithChecks(3)); err != nil {
		t.Fatal(err)
	}
	// Now "receive" a transient empty generation — Save must be a no-op.
	if err := c.Save(&collectorv1.CollectorConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(nil); err != nil {
		t.Fatal(err)
	}

	got, err := c.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.GetChecks()) != 3 {
		t.Fatalf("good cache was clobbered by empty save: %+v", got)
	}
}

// TestLoadFirstBootReturnsNil verifies Load returns (nil, nil) when no cache
// file exists yet (cold start, never persisted).
func TestLoadFirstBootReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.pb")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Load()
	if err != nil {
		t.Fatalf("Load on missing file should not error, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil config on first boot, got %+v", got)
	}
}

// TestSaveCreatesParentDir verifies New creates a missing parent directory so
// the first Save never fails on a fresh host.
func TestSaveCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "config-cache.pb")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save(cfgWithChecks(1)); err != nil {
		t.Fatalf("Save into freshly created dir failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected cache file at %s: %v", path, err)
	}
}
