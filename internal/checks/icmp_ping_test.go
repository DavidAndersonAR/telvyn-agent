package checks

import (
	"context"
	"os"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Teste 1-3: Factory comportamento (defaults, custom values, target ausente).
func TestIcmpPing_Factory(t *testing.T) {
	cases := []struct {
		name             string
		cfg              *collectorv1.CheckConfig
		wantErrContains  string
		wantTarget       string
		wantCount        int
		wantPacketIntMs  int
		wantInterval     time.Duration
		wantID           string
		wantStaticTagKey string
	}{
		{
			name: "defaults aplicados quando params opcionais ausentes",
			cfg: &collectorv1.CheckConfig{
				CheckId:    "ping-loopback",
				CheckType:  "icmp.ping",
				Interval:   durationpb.New(60 * time.Second),
				Enabled:    true,
				HostId:     "host-1",
				StaticTags: map[string]string{"env": "test"},
				Params:     map[string]string{"target": "127.0.0.1"},
			},
			wantTarget:       "127.0.0.1",
			wantCount:        10,
			wantPacketIntMs:  200,
			wantInterval:     60 * time.Second,
			wantID:           "ping-loopback",
			wantStaticTagKey: "env",
		},
		{
			name: "params custom sobrescrevem defaults",
			cfg: &collectorv1.CheckConfig{
				CheckType: "icmp.ping",
				Interval:  durationpb.New(0),
				Enabled:   true,
				HostId:    "host-2",
				Params: map[string]string{
					"target":             "10.0.0.1",
					"count":              "20",
					"packet_interval_ms": "100",
				},
			},
			wantTarget:      "10.0.0.1",
			wantCount:       20,
			wantPacketIntMs: 100,
			wantInterval:    30 * time.Second, // default quando Interval=0
			wantID:          "icmp.ping-host-2",
		},
		{
			name: "target ausente retorna erro",
			cfg: &collectorv1.CheckConfig{
				CheckType: "icmp.ping",
				Interval:  durationpb.New(30 * time.Second),
				Enabled:   true,
				HostId:    "host-3",
				Params:    map[string]string{},
			},
			wantErrContains: "missing param 'target'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newIcmpPingCheck(tc.cfg)
			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !contains(err.Error(), tc.wantErrContains) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected factory error: %v", err)
			}
			ic, ok := c.(*icmpPingCheck)
			if !ok {
				t.Fatalf("factory returned wrong type: %T", c)
			}
			if ic.target != tc.wantTarget {
				t.Errorf("target=%q want %q", ic.target, tc.wantTarget)
			}
			if ic.count != tc.wantCount {
				t.Errorf("count=%d want %d", ic.count, tc.wantCount)
			}
			if ic.packetInterval != time.Duration(tc.wantPacketIntMs)*time.Millisecond {
				t.Errorf("packetInterval=%v want %dms", ic.packetInterval, tc.wantPacketIntMs)
			}
			if c.Interval() != tc.wantInterval {
				t.Errorf("Interval()=%v want %v", c.Interval(), tc.wantInterval)
			}
			if tc.wantID != "" && c.ID() != tc.wantID {
				t.Errorf("ID()=%q want %q", c.ID(), tc.wantID)
			}
			if tc.wantStaticTagKey != "" {
				if _, present := c.Tags()[tc.wantStaticTagKey]; !present {
					t.Errorf("Tags() missing key %q", tc.wantStaticTagKey)
				}
			}
		})
	}
}

// Teste 4: Run() loopback emite as 6 métricas esperadas. Gated por ICMP_TEST
// porque requer CAP_NET_RAW (raw socket) — não disponível em CI nem em
// dev sem privilégio.
func TestIcmpPing_Run_Loopback(t *testing.T) {
	if os.Getenv("ICMP_TEST") == "" {
		t.Skip("set ICMP_TEST=1 to run; requires CAP_NET_RAW or root")
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "loop",
		CheckType: "icmp.ping",
		Interval:  durationpb.New(30 * time.Second),
		Enabled:   true,
		HostId:    "host-loop",
		Params: map[string]string{
			"target":             "127.0.0.1",
			"count":              "3",
			"packet_interval_ms": "100",
		},
	}
	c, err := newIcmpPingCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metrics, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	expected := map[string]bool{
		"icmp.rtt_avg_ms":    false,
		"icmp.rtt_min_ms":    false,
		"icmp.rtt_max_ms":    false,
		"icmp.rtt_stddev_ms": false,
		"icmp.loss_pct":      false,
		"icmp.jitter_ms":     false,
	}
	for _, m := range metrics {
		if _, ok := expected[m.MetricName]; ok {
			expected[m.MetricName] = true
		}
	}
	for name, present := range expected {
		if !present {
			t.Errorf("missing expected metric %q", name)
		}
	}
}

// Teste 5: ctx cancelado durante Run() retorna rapidamente (< 1s) com
// context.Canceled. Target = TEST-NET-1 (192.0.2.1) garantido sem resposta.
// Pulado quando não há permissão de raw socket — sem privilégio, NewPinger
// falha antes do select de cancel e o teste vira false-negative.
func TestIcmpPing_Run_CtxCancel(t *testing.T) {
	if os.Getenv("ICMP_TEST") == "" {
		t.Skip("set ICMP_TEST=1 to run; requires CAP_NET_RAW or root for raw socket")
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "cancel",
		CheckType: "icmp.ping",
		Interval:  durationpb.New(30 * time.Second),
		Enabled:   true,
		HostId:    "host-cancel",
		Params: map[string]string{
			"target":             "192.0.2.1",
			"count":              "100",
			"packet_interval_ms": "200",
			"timeout_seconds":    "30",
		},
	}
	c, err := newIcmpPingCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err = c.Run(ctx)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("Run took %v after cancel, expected <1s", elapsed)
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// Teste 6: factory auto-registrada em Default.
func TestIcmpPing_Registry(t *testing.T) {
	factory, ok := Default.Get("icmp.ping")
	if !ok {
		t.Fatal("icmp.ping not registered in Default")
	}
	if factory == nil {
		t.Fatal("registered factory is nil")
	}
}

// contains é helper local pra evitar import de strings só pra um substring check.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
