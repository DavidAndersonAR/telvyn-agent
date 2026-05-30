// icmp_scan.go — Check "icmp.scan" — autodescoberta por ICMP echo.
//
// Diferente do snmp.autodiscover (que precisa de SNMP daemon respondendo
// no alvo), icmp.scan acha qualquer host pingavel. Util pra:
//   - Inventario inicial em redes mistas (containers, VMs, devices sem SNMP)
//   - Bootstrap antes de configurar SNMP nos alvos
//   - Verificar se a CIDR esta no escopo certo
//
// Emite Events host.discovered (mesmo event_type do snmp.autodiscover) com
// details = {"source": "icmp", "rtt_ms": <avg-rtt>}. AutodiscoveryHandler
// no Quarkus aceita event sem sys_object_id — interpretado como descoberto
// por ICMP-only.
//
// Pacote `pro-bing` (mesmo usado por icmp.ping). Precisa CAP_NET_RAW —
// systemd unit do agent ja seta AmbientCapabilities=CAP_NET_RAW.
package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	icmpScanDefaultConcurrency  = 50
	icmpScanDefaultPerHostMs    = 500
	icmpScanDefaultPacketCount  = 1
)

type icmpScanCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string

	cidrs       []string
	concurrency int
	perHost     time.Duration
	count       int
	runOnce     bool
	done        atomic.Bool
}

func newIcmpScanCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	rawCidrs := strings.TrimSpace(params["cidrs"])
	if rawCidrs == "" {
		return nil, fmt.Errorf("icmp.scan: param 'cidrs' obrigatorio (CSV de CIDRs)")
	}
	parts := strings.Split(rawCidrs, ",")
	cidrs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err != nil {
			return nil, fmt.Errorf("icmp.scan: CIDR invalido %q: %w", p, err)
		}
		cidrs = append(cidrs, p)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("icmp.scan: param 'cidrs' parseado vazio")
	}

	concurrency := atoiDefault(params["concurrency"], icmpScanDefaultConcurrency)
	perHostMs := atoiDefault(params["per_host_timeout_ms"], icmpScanDefaultPerHostMs)
	count := atoiDefault(params["count"], icmpScanDefaultPacketCount)

	runOnce := strings.EqualFold(strings.TrimSpace(params["run_once"]), "true")

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		// Scans icmp tendem a ser ate mais leves que SNMP, mas mantemos
		// cadencia comportada — 5min default. Operador sobrescreve via UI.
		interval = 5 * time.Minute
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "icmp.scan-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &icmpScanCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		staticTags:  tags,
		cidrs:       cidrs,
		concurrency: concurrency,
		perHost:     time.Duration(perHostMs) * time.Millisecond,
		count:       count,
		runOnce:     runOnce,
	}, nil
}

func (c *icmpScanCheck) ID() string              { return c.id }
func (c *icmpScanCheck) Interval() time.Duration { return c.interval }
func (c *icmpScanCheck) Tags() map[string]string { return c.staticTags }

// Run pinga cada IP nas CIDRs com `count` pacotes e timeout `perHost`. IPs
// que respondem viram Events host.discovered.
func (c *icmpScanCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if c.runOnce && c.done.Load() {
		return nil, nil
	}

	type alive struct {
		ip    string
		rttMs float64
	}

	ips, err := expandCIDRs(c.cidrs)
	if err != nil {
		return nil, fmt.Errorf("icmp.scan expand cidrs: %w", err)
	}

	results := make(chan alive, len(ips))
	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			pinger, perr := probing.NewPinger(target)
			if perr != nil {
				return
			}
			pinger.SetPrivileged(true)
			pinger.Count = c.count
			pinger.Timeout = c.perHost
			pinger.Interval = 50 * time.Millisecond
			if err := pinger.RunWithContext(ctx); err != nil {
				return
			}
			stats := pinger.Statistics()
			if stats.PacketsRecv > 0 {
				results <- alive{ip: target, rttMs: float64(stats.AvgRtt.Microseconds()) / 1000.0}
			}
		}(ip)
	}
	wg.Wait()
	close(results)

	if c.runOnce {
		c.done.Store(true)
	}

	events := make([]*collectorv1.Event, 0, 16)
	now := timestamppb.Now()
	for r := range results {
		details, derr := structpb.NewStruct(map[string]interface{}{
			"source": "icmp",
			"rtt_ms": r.rttMs,
		})
		if derr != nil {
			continue
		}
		events = append(events, &collectorv1.Event{
			Time:      now,
			HostId:    r.ip,
			EventType: "host.discovered",
			Severity:  "info",
			Details:   details,
		})
	}

	if len(events) == 0 {
		return nil, nil
	}

	ch := EventsChannel()
	if ch == nil {
		return nil, nil
	}
	select {
	case ch <- events:
	default:
		// Consumidor lento — drop com warn (caller log de batch full)
	}
	return nil, nil
}

// expandCIDRs gera lista de IPs cobertos pelas CIDRs informadas. Para /24
// gera 254 IPs (skip network + broadcast). Por seguranca limita a 4096
// IPs totais — alem disso retorna erro pra evitar scan inadvertido em /16.
func expandCIDRs(cidrs []string) ([]string, error) {
	const maxIPs = 4096
	out := make([]string, 0, 64)
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", c, err)
		}
		ip := ipNet.IP.Mask(ipNet.Mask)
		for ; ipNet.Contains(ip); incIP(ip) {
			// skip network address (.0) e broadcast em /24 (.255)
			last := ip[len(ip)-1]
			ones, bits := ipNet.Mask.Size()
			if bits == 32 && ones < 31 && (last == 0 || last == 255) {
				continue
			}
			out = append(out, ip.String())
			if len(out) > maxIPs {
				return nil, fmt.Errorf("icmp.scan: limite de %d IPs excedido (use CIDR menor)", maxIPs)
			}
		}
	}
	return out, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func init() {
	Default.Register("icmp.scan", newIcmpScanCheck)
}
