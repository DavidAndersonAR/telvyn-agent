package checks

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/discovery"
)

// withScanFunc substitui o scan func + restaura no defer.
func withScanFunc(t *testing.T, fn scanSNMPFn) {
	t.Helper()
	orig := scanSNMP
	scanSNMP = fn
	t.Cleanup(func() { scanSNMP = orig })
}

func TestAutodiscover_RegisteredInDefault(t *testing.T) {
	if _, ok := Default.Get("snmp.autodiscover"); !ok {
		t.Fatal("snmp.autodiscover not registered in Default")
	}
}

func TestAutodiscover_FactoryParsesParams(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-1",
		CheckType: "snmp.autodiscover",
		HostId:    "host-1",
		Enabled:   true,
		Params: map[string]string{
			"cidrs":              "10.0.0.0/30,192.168.1.0/30",
			"community":          "public",
			"version":            "v2c",
			"concurrency":        "20",
			"per_host_timeout_ms": "500",
			"batch_sleep_ms":     "25",
			"run_once":           "true",
		},
	}
	c, err := newSnmpAutodiscoverCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ad := c.(*snmpAutodiscoverCheck)
	if len(ad.cidrs) != 2 {
		t.Fatalf("expected 2 cidrs, got %v", ad.cidrs)
	}
	if ad.scanParams.Concurrency != 20 || ad.scanParams.PerHostTimeout != 500*time.Millisecond {
		t.Fatalf("scanParams mismatch: %+v", ad.scanParams)
	}
	if ad.scanParams.BatchSleep != 25*time.Millisecond {
		t.Fatalf("BatchSleep mismatch: %v", ad.scanParams.BatchSleep)
	}
	if !ad.runOnce {
		t.Fatal("runOnce should be true")
	}
}

func TestAutodiscover_FactoryDefaultsApplied(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-2",
		CheckType: "snmp.autodiscover",
		Enabled:   true,
		Params: map[string]string{
			"cidrs":     "10.0.0.0/30",
			"community": "public",
		},
	}
	c, err := newSnmpAutodiscoverCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ad := c.(*snmpAutodiscoverCheck)
	if ad.runOnce {
		t.Fatal("runOnce default should be false")
	}
	if ad.interval <= 0 {
		t.Fatal("interval default missing")
	}
}

func TestAutodiscover_FactoryRequiresCIDRs(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-3",
		CheckType: "snmp.autodiscover",
		Enabled:   true,
		Params: map[string]string{
			"community": "public",
		},
	}
	if _, err := newSnmpAutodiscoverCheck(cfg); err == nil {
		t.Fatal("expected error when cidrs missing")
	}
}

func TestAutodiscover_RunEmitsHostDiscoveredEvents(t *testing.T) {
	withScanFunc(t, func(ctx context.Context, cidrs []string, p discovery.ScanParams) ([]discovery.Candidate, error) {
		return []discovery.Candidate{
			{IP: "10.0.0.1", SysObjectID: "1.3.6.1.4.1.14988.1", ProfileSuggestion: "mikrotik-routeros", Port: 161, DiscoveredAt: time.Now()},
			{IP: "10.0.0.2", SysObjectID: "1.3.6.1.4.1.999", ProfileSuggestion: "", Port: 161, DiscoveredAt: time.Now()},
		}, nil
	})

	// Canal de events buffered + setar via singleton.
	evCh := make(chan []*collectorv1.Event, 4)
	SetEventsChannel(evCh)
	defer SetEventsChannel(nil)

	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-4",
		CheckType: "snmp.autodiscover",
		HostId:    "host-x",
		Enabled:   true,
		Params: map[string]string{
			"cidrs":     "10.0.0.0/30",
			"community": "public",
		},
	}
	c, err := newSnmpAutodiscoverCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("expected zero metrics (autodiscover so emite Events), got %d", len(metrics))
	}

	var got []*collectorv1.Event
	select {
	case got = <-evCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no events emitted")
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	for _, e := range got {
		if e.GetEventType() != "host.discovered" {
			t.Fatalf("event_type=%q want host.discovered", e.GetEventType())
		}
		if e.GetSeverity() != "info" {
			t.Fatalf("severity=%q want info", e.GetSeverity())
		}
		if e.GetHostId() == "" {
			t.Fatal("empty host_id")
		}
		fields := e.GetDetails().GetFields()
		if _, ok := fields["sysobjectid"]; !ok {
			t.Fatal("details.sysobjectid missing")
		}
		if _, ok := fields["profile_suggestion"]; !ok {
			t.Fatal("details.profile_suggestion missing")
		}
	}
}

func TestAutodiscover_RunOnceSkipsSecondRun(t *testing.T) {
	var calls atomic.Int64
	withScanFunc(t, func(ctx context.Context, cidrs []string, p discovery.ScanParams) ([]discovery.Candidate, error) {
		calls.Add(1)
		return []discovery.Candidate{{IP: "10.0.0.1", SysObjectID: "x", Port: 161}}, nil
	})

	evCh := make(chan []*collectorv1.Event, 4)
	SetEventsChannel(evCh)
	defer SetEventsChannel(nil)

	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-5",
		CheckType: "snmp.autodiscover",
		Enabled:   true,
		Params: map[string]string{
			"cidrs":     "10.0.0.0/30",
			"community": "public",
			"run_once":  "true",
		},
	}
	c, _ := newSnmpAutodiscoverCheck(cfg)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 scan invocation (runOnce), got %d", calls.Load())
	}
}

func TestAutodiscover_RunWithoutEventsChannelIsSilent(t *testing.T) {
	withScanFunc(t, func(ctx context.Context, cidrs []string, p discovery.ScanParams) ([]discovery.Candidate, error) {
		return []discovery.Candidate{{IP: "10.0.0.1", SysObjectID: "x", Port: 161}}, nil
	})
	// Sem SetEventsChannel — Run nao deve panic; deve apenas ignorar.
	SetEventsChannel(nil)

	cfg := &collectorv1.CheckConfig{
		CheckId:   "ad-6",
		CheckType: "snmp.autodiscover",
		Enabled:   true,
		Params: map[string]string{
			"cidrs":     "10.0.0.0/30",
			"community": "public",
		},
	}
	c, _ := newSnmpAutodiscoverCheck(cfg)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
