// tcp_connect.go — Check "tcp.connect" para link_probe.
//
// Mede tempo de handshake TCP a partir de uma interface/IP de origem
// especificos (source binding). Util para detectar latencia de uplink
// quando ICMP esta filtrado pelo provedor mas TCP/443 esta aberto.
//
// Metricas:
//   tcp.connect_ms   - tempo do handshake (so quando success=1)
//   tcp.success      - 0/1 (1 = SYN+SYN-ACK+ACK completado)

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

type tcpConnectCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	target      string
	timeout     time.Duration
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

func newTCPConnectCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("tcp.connect: missing param 'target'")
	}
	if !strings.Contains(target, ":") {
		return nil, fmt.Errorf("tcp.connect: target must be host:port (got %q)", target)
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "tcp.connect-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &tcpConnectCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		target:      target,
		timeout:     parseTimeoutMs(params, 3000),
		sourceIface: params["source_iface"],
		sourceIP:    params["source_ip"],
		staticTags:  tags,
	}, nil
}

func (c *tcpConnectCheck) ID() string              { return c.id }
func (c *tcpConnectCheck) Interval() time.Duration { return c.interval }
func (c *tcpConnectCheck) Tags() map[string]string { return c.staticTags }

func (c *tcpConnectCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	dialer := newBindingDialer(c.sourceIface, c.sourceIP, c.timeout)

	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", c.target)
	elapsed := time.Since(start)

	now := timestamppb.Now()
	if err != nil {
		// Dial falhou: success=0, sem connect_ms. Mantemos a metrica
		// connect_ms zerada porque o backend usa COUNT/AVG e zero diluiria
		// — emitimos so success.
		return []*collectorv1.Metric{
			c.metric(now, "tcp.success", 0),
		}, nil
	}
	_ = conn.Close()

	return []*collectorv1.Metric{
		c.metric(now, "tcp.connect_ms", float64(elapsed)/float64(time.Millisecond)),
		c.metric(now, "tcp.success", 1),
	}, nil
}

func (c *tcpConnectCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
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
		Source:     "tcp",
	}
}

// Ensure net is reachable for the linter when this file compiles solo.
var _ = net.Dial

func init() {
	Default.Register("tcp.connect", newTCPConnectCheck)
}
