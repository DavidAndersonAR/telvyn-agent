// icmp_ping.go — Check "icmp.ping" implementação contínua.
//
// Coleta reachability + qualidade de link (RTT/jitter/loss) via ICMP echo,
// emitindo 6 métricas por ciclo:
//   - icmp.rtt_avg_ms / icmp.rtt_min_ms / icmp.rtt_max_ms / icmp.rtt_stddev_ms
//   - icmp.loss_pct (0-100)
//   - icmp.jitter_ms (V0 = StdDevRtt como proxy; RFC 3550 inter-arrival
//     jitter via OnRecv callback é refinamento deferido pós-feedback ops)
//
// Decisão de runtime (CONTEXT.md/RESEARCH.md Pitfall 2): usa raw socket
// privilegiado via pinger.SetPrivileged(true). Isso exige CAP_NET_RAW
// concedido pelo systemd unit (Plan 08 do Phase 3 — AmbientCapabilities=
// CAP_NET_RAW). Evitamos depender de net.ipv4.ping_group_range sysctl
// que muitos kernels não trazem default, e o install.sh não mexe em
// kernel tunables do cliente.
//
// Compatível com framework Phase 2 (checks.Check + Registry + Runtime).
package checks

import (
	"context"
	"fmt"
	"strconv"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultPingCount        = 10
	defaultPacketIntervalMs = 200
	// pad em segundos sobre count*packetInterval pra cobrir DNS resolve
	// + handshake + reply window dos últimos pacotes.
	defaultPingTimeoutPadSeconds = 2
)

// icmpPingCheck é a implementação concreta de Check para "icmp.ping".
type icmpPingCheck struct {
	id             string
	interval       time.Duration
	hostID         string
	target         string
	count          int
	packetInterval time.Duration
	timeout        time.Duration
	// Source binding pra teste de uplink (link_probe). Quando setado, o
	// pinger envia pelos endereços/interfaces selecionados — necessario
	// pra testar Vivo vs BrisaNet vs Mob num collector multi-NIC.
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

// newIcmpPingCheck é a Factory registrada em init() para "icmp.ping".
// Valida `target` (obrigatório) e parseia params opcionais com defaults.
func newIcmpPingCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := params["target"]
	if target == "" {
		return nil, fmt.Errorf("icmp.ping: missing param 'target'")
	}

	count := parseIntParam(params, "count", defaultPingCount)
	if count <= 0 {
		count = defaultPingCount
	}
	packetIntervalMs := parseIntParam(params, "packet_interval_ms", defaultPacketIntervalMs)
	if packetIntervalMs <= 0 {
		packetIntervalMs = defaultPacketIntervalMs
	}
	packetInterval := time.Duration(packetIntervalMs) * time.Millisecond

	// timeout default = count * packetInterval + pad. Operador pode
	// sobrescrever via param "timeout_seconds".
	defaultTimeoutSec := (count*packetIntervalMs)/1000 + defaultPingTimeoutPadSeconds
	timeoutSec := parseIntParam(params, "timeout_seconds", defaultTimeoutSec)
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	timeout := time.Duration(timeoutSec) * time.Second

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "icmp.ping-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &icmpPingCheck{
		id:             id,
		interval:       interval,
		hostID:         cfg.GetHostId(),
		target:         target,
		count:          count,
		packetInterval: packetInterval,
		timeout:        timeout,
		sourceIface:    params["source_iface"],
		sourceIP:       params["source_ip"],
		staticTags:     tags,
	}, nil
}

func (c *icmpPingCheck) ID() string              { return c.id }
func (c *icmpPingCheck) Interval() time.Duration { return c.interval }
func (c *icmpPingCheck) Tags() map[string]string { return c.staticTags }

// Run executa um ciclo de ping: bloqueia até completar Count packets ou até
// Timeout do pinger. Honra ctx.Done() rodando pinger.Run em goroutine e
// chamando pinger.Stop() no cancel — assim runtime de checks não vaza
// goroutine durante shutdown/reload (mesma semântica do scheduler Phase 2).
//
// PacketsRecv == 0 ainda emite todas as métricas (loss_pct=100, RTTs=0):
// o backend trata 100% loss como sinal explícito, não como ausência.
func (c *icmpPingCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	pinger, err := probing.NewPinger(c.target)
	if err != nil {
		return nil, fmt.Errorf("icmp.ping: NewPinger(%q): %w", c.target, err)
	}
	pinger.Count = c.count
	pinger.Interval = c.packetInterval
	pinger.Timeout = c.timeout

	// Source binding para uplinks multi-NIC (link_probe). InterfaceName
	// usa SO_BINDTODEVICE (Linux, exige CAP_NET_RAW — ja temos). Source
	// e o IP local que o pinger usa como origem; util quando o collector
	// tem multiplos IPs e a rota default escolheria o errado.
	if c.sourceIface != "" {
		pinger.InterfaceName = c.sourceIface
	}
	if c.sourceIP != "" {
		pinger.Source = c.sourceIP
	}

	// Decisão locked (RESEARCH §Pitfall 2): raw socket privilegiado via
	// CAP_NET_RAW concedida pelo systemd unit (Plan 08). Não usamos UDP
	// unprivileged porque depende de sysctl net.ipv4.ping_group_range
	// que muitos kernels não trazem default.
	pinger.SetPrivileged(true)

	done := make(chan error, 1)
	go func() {
		done <- pinger.Run()
	}()

	select {
	case <-ctx.Done():
		pinger.Stop()
		// Espera goroutine terminar pra garantir limpeza determinística;
		// pinger.Stop() faz Run() retornar logo.
		<-done
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("icmp.ping: run %q: %w", c.target, err)
		}
	}

	stats := pinger.Statistics()
	now := timestamppb.Now()

	rttAvgMs := durationToMs(stats.AvgRtt)
	rttMinMs := durationToMs(stats.MinRtt)
	rttMaxMs := durationToMs(stats.MaxRtt)
	rttStdDevMs := durationToMs(stats.StdDevRtt)
	// V0: jitter = StdDevRtt como proxy. RFC 3550 inter-arrival jitter via
	// pinger.OnRecv samples é refinamento futuro quando ops pedir.
	jitterMs := rttStdDevMs

	return []*collectorv1.Metric{
		c.metric(now, "icmp.rtt_avg_ms", rttAvgMs),
		c.metric(now, "icmp.rtt_min_ms", rttMinMs),
		c.metric(now, "icmp.rtt_max_ms", rttMaxMs),
		c.metric(now, "icmp.rtt_stddev_ms", rttStdDevMs),
		c.metric(now, "icmp.loss_pct", stats.PacketLoss),
		c.metric(now, "icmp.jitter_ms", jitterMs),
	}, nil
}

// metric constrói um Metric com static tags + tag "target" (identifica o
// alvo pra dashboards/correlation engine) + source="icmp".
func (c *icmpPingCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+1)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["target"] = c.target
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "icmp",
	}
}

// durationToMs converte time.Duration para milissegundos float (RTT humano).
func durationToMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// parseIntParam lê um param string como int, retornando def quando ausente
// ou inválido (formato robusto: operador errou typing → cai no default).
func parseIntParam(params map[string]string, key string, def int) int {
	raw, ok := params[key]
	if !ok || raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

// init auto-registra o factory em Default. Cada integração é autocontida
// (cada package de check registra a si mesmo).
func init() {
	Default.Register("icmp.ping", newIcmpPingCheck)
}
