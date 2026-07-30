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
//   dns.match       - 0/1, SO quando expected_ips vem preenchido (ver abaixo)
//
// Params:
//   target          - nome a resolver (ex: "google.com")
//   server          - servidor DNS (opcional, ex: "8.8.8.8:53"); default
//                     usa o resolver do sistema, que com source binding
//                     continua respeitando o /etc/resolv.conf
//   expected_ips    - lista separada por virgula (ex: "203.0.113.10, 203.0.113.11").
//                     Vazio = nao emite dns.match, e o check se comporta
//                     exatamente como antes.
//   source_iface    - SO_BINDTODEVICE
//   source_ip       - net.Dialer.LocalAddr
//   timeout_ms      - default 3000
//
// SEMANTICA DO dns.match: 1 exige que a resposta nao seja vazia E que TODO IP
// retornado esteja na lista. Nao e "pelo menos um" de proposito — num sequestro
// de DNS o IP legitimo costuma continuar na resposta, com o falso ao lado;
// exigir o conjunto inteiro pega esse caso, "pelo menos um" nao pegaria.

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
	server      string   // host:port; "" -> usa system resolver
	expectedIPs []string // vazio = nao emite dns.match
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
		expectedIPs: parseExpectedIPs(params["expected_ips"]),
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
		out := []*collectorv1.Metric{
			c.metric(now, "dns.rtt_ms", float64(elapsed)/float64(time.Millisecond)),
			c.metric(now, "dns.answers", 0),
			c.metric(now, "dns.error", 1),
		}
		// Nao resolveu, logo nao casou: quem pediu conferencia de IP precisa
		// ver 0 aqui, senao o alerta de "IP errado" ficaria cego a NXDOMAIN.
		if len(c.expectedIPs) > 0 {
			out = append(out, c.metric(now, "dns.match", 0))
		}
		return out, nil
	}
	out := []*collectorv1.Metric{
		c.metric(now, "dns.rtt_ms", float64(elapsed)/float64(time.Millisecond)),
		c.metric(now, "dns.answers", float64(len(ips))),
		c.metric(now, "dns.error", 0),
	}
	if len(c.expectedIPs) > 0 {
		match := 0.0
		if ipsAllExpected(ips, c.expectedIPs) {
			match = 1
		}
		out = append(out, c.metric(now, "dns.match", match))
	}
	return out, nil
}

// parseExpectedIPs quebra a lista do formulario. Tolerante com espaco e virgula
// sobrando porque o campo e digitado a mao.
func parseExpectedIPs(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ipsAllExpected: resposta nao vazia E todo IP retornado presente na lista.
// Compara por net.IP e nao por string — "203.0.113.10" e "::ffff:203.0.113.10"
// sao o mesmo endereco, e IPv6 tem varias grafias pro mesmo valor.
func ipsAllExpected(got []net.IPAddr, expected []string) bool {
	if len(got) == 0 {
		return false
	}
	allowed := make([]net.IP, 0, len(expected))
	for _, e := range expected {
		if ip := net.ParseIP(e); ip != nil {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return false // lista só com lixo digitado: nao da pra afirmar que casou
	}
	for _, g := range got {
		found := false
		for _, a := range allowed {
			if g.IP.Equal(a) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
