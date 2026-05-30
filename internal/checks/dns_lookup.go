// dns_lookup.go — Check "dns.lookup" para link_probe.
//
// Resolve um nome (A/AAAA) usando um resolver com socket bind pela
// interface/IP do uplink. Mede latencia e captura quando o DNS retorna
// SERVFAIL/NXDOMAIN, sinal de que o link esta saindo mas o downstream
// do provedor esta com problema.
//
// Metricas:
//   dns.rtt_ms      - latencia ate a primeira resposta
//   dns.answers     - quantidade de IPs retornados (0 quando erro)
//   dns.error       - 0/1 (1 = falha ou nxdomain)
//
// Params:
//   target          - nome a resolver (ex: "google.com")
//   server          - servidor DNS (opcional, ex: "8.8.8.8:53"); default
//                     usa o resolver do sistema, que com source binding
//                     continua respeitando o /etc/resolv.conf
//   source_iface    - SO_BINDTODEVICE
//   source_ip       - net.Dialer.LocalAddr
//   timeout_ms      - default 3000

package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type dnsLookupCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	target      string
	server      string // host:port; "" -> usa system resolver
	timeout     time.Duration
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

func newDNSLookupCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("dns.lookup: missing param 'target'")
	}

	server := strings.TrimSpace(params["server"])
	if server != "" && !strings.Contains(server, ":") {
		server = server + ":53"
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "dns.lookup-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &dnsLookupCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		target:      target,
		server:      server,
		timeout:     parseTimeoutMs(params, 3000),
		sourceIface: params["source_iface"],
		sourceIP:    params["source_ip"],
		staticTags:  tags,
	}, nil
}

func (c *dnsLookupCheck) ID() string              { return c.id }
func (c *dnsLookupCheck) Interval() time.Duration { return c.interval }
func (c *dnsLookupCheck) Tags() map[string]string { return c.staticTags }

func (c *dnsLookupCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	dialer := newBindingDialer(c.sourceIface, c.sourceIP, c.timeout)

	resolver := &net.Resolver{
		PreferGo: true, // forca uso do dialer custom (cgo resolver ignora-o)
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := address
			if c.server != "" {
				addr = c.server
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupIPAddr(dialCtx, c.target)
	elapsed := time.Since(start)

	now := timestamppb.Now()
	if err != nil {
		return []*collectorv1.Metric{
			c.metric(now, "dns.rtt_ms", float64(elapsed)/float64(time.Millisecond)),
			c.metric(now, "dns.answers", 0),
			c.metric(now, "dns.error", 1),
		}, nil
	}
	return []*collectorv1.Metric{
		c.metric(now, "dns.rtt_ms", float64(elapsed)/float64(time.Millisecond)),
		c.metric(now, "dns.answers", float64(len(ips))),
		c.metric(now, "dns.error", 0),
	}, nil
}

func (c *dnsLookupCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+2)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["target"] = c.target
	if c.server != "" {
		tags["server"] = c.server
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "dns",
	}
}

func init() {
	Default.Register("dns.lookup", newDNSLookupCheck)
}
