package discovery

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ispwatch/collector/internal/snmp"
)

// fakeProbe e o stub injetado em testes via clientFactory. Responde de acordo
// com a func GetFn passada — sem socket UDP envolvido.
type fakeProbe struct {
	target string
	getFn  func(target string) ([]gosnmp.SnmpPDU, error)
}

func (f *fakeProbe) GetSysObjectID(ctx context.Context) (string, error) {
	pdus, err := f.getFn(f.target)
	if err != nil {
		return "", err
	}
	if len(pdus) == 0 {
		return "", errors.New("snmp: empty")
	}
	return pdus[0].Value.(string), nil
}

func (f *fakeProbe) Close() error { return nil }

// withFactory substitui clientFactory durante o teste e restaura no defer.
func withFactory(t *testing.T, fn func(snmp.Params) (snmpProbe, error)) {
	t.Helper()
	orig := clientFactory
	clientFactory = fn
	t.Cleanup(func() { clientFactory = orig })
}

// ----- hostsInCIDR -----------------------------------------------------

func TestHostsInCIDR_Slash29(t *testing.T) {
	hosts, err := hostsInCIDR("192.0.2.0/29")
	if err != nil {
		t.Fatalf("hostsInCIDR: %v", err)
	}
	// /29 = 8 addresses; minus network (.0) and broadcast (.7) = 6 hosts.
	if len(hosts) != 6 {
		t.Fatalf("/29 expected 6 hosts, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "192.0.2.1" || hosts[5] != "192.0.2.6" {
		t.Fatalf("/29 unexpected range: first=%s last=%s", hosts[0], hosts[5])
	}
}

func TestHostsInCIDR_Slash32(t *testing.T) {
	hosts, err := hostsInCIDR("192.0.2.5/32")
	if err != nil {
		t.Fatalf("hostsInCIDR: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "192.0.2.5" {
		t.Fatalf("/32 expected [192.0.2.5], got %v", hosts)
	}
}

func TestHostsInCIDR_Slash31(t *testing.T) {
	hosts, err := hostsInCIDR("192.0.2.0/31")
	if err != nil {
		t.Fatalf("hostsInCIDR: %v", err)
	}
	// /31 — point-to-point (RFC 3021); ambos endereços são válidos.
	if len(hosts) != 2 {
		t.Fatalf("/31 expected 2 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestHostsInCIDR_Invalid(t *testing.T) {
	if _, err := hostsInCIDR("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// ----- ScanSNMP --------------------------------------------------------

func TestScanSNMP_ProbesEveryIP(t *testing.T) {
	var calls atomic.Int64
	var seen sync.Map

	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		calls.Add(1)
		// Target tem ":161" anexado pelo scan.
		host := p.Target
		seen.Store(host, true)
		// Retorna sysObjectID de um Mikrotik conhecido (sem match) — generic.
		return &fakeProbe{
			target: host,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.99999.1"}}, nil
			},
		}, nil
	})

	ctx := context.Background()
	// /30 — 4 addresses, hostsInCIDR trim network + broadcast → 2 hosts.
	cands, err := ScanSNMP(ctx, []string{"192.0.2.0/30"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    10,
		PerHostTimeout: 100 * time.Millisecond,
		BatchSleep:     0,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 probes, got %d", got)
	}
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
}

func TestScanSNMP_SkipsErrors(t *testing.T) {
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		// Metade falha, metade responde.
		if p.Target == "192.0.2.1:161" {
			return &fakeProbe{
				target: p.Target,
				getFn: func(string) ([]gosnmp.SnmpPDU, error) {
					return nil, errors.New("timeout")
				},
			}, nil
		}
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.8072.3.2.10"}}, nil // net-snmp
			},
		}, nil
	})

	cands, err := ScanSNMP(context.Background(), []string{"192.0.2.0/30"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    10,
		PerHostTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	// /30 = .1 e .2 (2 hosts). .1 falha, .2 vira candidate.
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate (other timed out), got %d: %v", len(cands), cands)
	}
	if cands[0].IP != "192.0.2.2" {
		t.Fatalf("expected ip=192.0.2.2, got %s", cands[0].IP)
	}
}

func TestScanSNMP_ProfileSuggestionMikrotik(t *testing.T) {
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				// sysObjectID Mikrotik — prefix 1.3.6.1.4.1.14988.1 deve casar mikrotik-routeros.
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.14988.1"}}, nil
			},
		}, nil
	})

	cands, err := ScanSNMP(context.Background(), []string{"192.0.2.0/32"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    1,
		PerHostTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if cands[0].ProfileSuggestion != "mikrotik-routeros" {
		t.Fatalf("expected ProfileSuggestion=mikrotik-routeros, got %q", cands[0].ProfileSuggestion)
	}
	if cands[0].SysObjectID == "" {
		t.Fatalf("SysObjectID empty")
	}
}

func TestScanSNMP_ContextCancel(t *testing.T) {
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		// Probe que demora — vai segurar a goroutine ate ctx cancel propagar.
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				time.Sleep(500 * time.Millisecond)
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.0"}}, nil
			},
		}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	start := time.Now()
	go func() {
		_, _ = ScanSNMP(ctx, []string{"192.0.2.0/28"}, ScanParams{
			Version:        "v2c",
			Community:      "public",
			Concurrency:    2,
			PerHostTimeout: 50 * time.Millisecond,
		})
		close(doneCh)
	}()

	// Cancela rapidamente.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-doneCh:
		// /28 com sleep 500ms por probe e concurrency=2 levaria varios segundos
		// sem cancelamento. Esperamos retorno em <1s apos cancel.
		if d := time.Since(start); d > 1*time.Second {
			t.Fatalf("cancel respected too slowly: %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ScanSNMP did not return after ctx cancel")
	}
}

func TestScanSNMP_BatchSleepRespected(t *testing.T) {
	var calls atomic.Int64
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		calls.Add(1)
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.0"}}, nil
			},
		}, nil
	})

	// /28 = 14 hosts; concurrency=4 + sleep=10ms → ao menos 3 batches → >=30ms.
	start := time.Now()
	_, err := ScanSNMP(context.Background(), []string{"192.0.2.0/28"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    4,
		PerHostTimeout: 10 * time.Millisecond,
		BatchSleep:     30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("BatchSleep not respected — elapsed %v < 60ms (calls=%d)", elapsed, calls.Load())
	}
}

func TestScanSNMP_NoMatchProfileEmpty(t *testing.T) {
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.999999.123"}}, nil
			},
		}, nil
	})

	cands, err := ScanSNMP(context.Background(), []string{"192.0.2.5/32"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    1,
		PerHostTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if cands[0].ProfileSuggestion != "" {
		t.Fatalf("expected empty ProfileSuggestion, got %q", cands[0].ProfileSuggestion)
	}
	if cands[0].SysObjectID != "1.3.6.1.4.1.999999.123" {
		t.Fatalf("SysObjectID wrong: %q", cands[0].SysObjectID)
	}
}

func TestScanSNMP_MultipleCIDRDedupes(t *testing.T) {
	var calls atomic.Int64
	withFactory(t, func(p snmp.Params) (snmpProbe, error) {
		calls.Add(1)
		return &fakeProbe{
			target: p.Target,
			getFn: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{{Value: "1.3.6.1.4.1.0"}}, nil
			},
		}, nil
	})
	// Overlapping CIDRs — mesma IP nao deve probar 2x.
	_, err := ScanSNMP(context.Background(), []string{"192.0.2.0/30", "192.0.2.0/30"}, ScanParams{
		Version:        "v2c",
		Community:      "public",
		Concurrency:    4,
		PerHostTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanSNMP: %v", err)
	}
	// /30 = 2 hosts (sem network/broadcast). Repetido nao adiciona.
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 unique probes, got %d (dedup falhou)", got)
	}
}

// helper para o teste de match exato — ajuda a evitar flaky por ordering.
func sortStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
