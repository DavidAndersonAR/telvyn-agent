// mtr.go — Check "mtr" para link_probe.
//
// Roda o binario `mtr` (My Traceroute) em modo report+JSON contra o target
// e extrai estatisticas hop-a-hop. Util para diagnosticar onde a perda
// comeca na rota do uplink — se Vivo perde no hop 3 dentro da rede deles,
// nao adianta abrir chamado dizendo "internet caiu".
//
// Decisao de runtime: shell-out vs. implementar traceroute em Go puro.
// `mtr` ja esta em quase todo Linux/BSD operacional e tem flag -I pra
// source interface. Implementar TTL stepping em Go puro seria ~150
// linhas a mais. Quando o binario nao existe (alpine minimal) emitimos
// metricas com mtr.available=0 — backend pode alertar "instale mtr no
// collector".
//
// Metricas (agregadas pelo destino final):
//   mtr.available         - 0/1 (1 = binario instalado e rodou)
//   mtr.hops              - quantidade de hops ate o destino
//   mtr.last_hop_loss_pct - perda no ultimo hop (destino)
//   mtr.last_hop_avg_ms   - RTT medio ate o destino
//   mtr.worst_hop_loss_pct - perda no pior hop intermediario
//
// Params:
//   target                  - IP ou hostname
//   cycles                  - default 3, no minimo 1
//   source_iface/source_ip  - source binding via mtr -I/-a
//   timeout_ms              - default 15000 (cycles*~packetinterval)

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type mtrCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	target      string
	cycles      int
	timeout     time.Duration
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

func newMTRCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("mtr: missing param 'target'")
	}
	cycles := parseIntParam(params, "cycles", 3)
	if cycles < 1 {
		cycles = 1
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "mtr-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &mtrCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		target:      target,
		cycles:      cycles,
		timeout:     parseTimeoutMs(params, 15000),
		sourceIface: params["source_iface"],
		sourceIP:    params["source_ip"],
		staticTags:  tags,
	}, nil
}

func (c *mtrCheck) ID() string              { return c.id }
func (c *mtrCheck) Interval() time.Duration { return c.interval }
func (c *mtrCheck) Tags() map[string]string { return c.staticTags }

// mtrReport — shape do JSON retornado por `mtr --report-json`. Mantemos
// um subset minimo dos campos que usamos.
type mtrReport struct {
	Report struct {
		Hubs []struct {
			Host string  `json:"host"`
			Loss float64 `json:"Loss%"`
			Avg  float64 `json:"Avg"`
		} `json:"hubs"`
	} `json:"report"`
}

func (c *mtrCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	mtrPath, err := exec.LookPath("mtr")
	if err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "mtr.available", 0)}, nil
	}

	args := []string{
		"--report",
		"--report-json",
		"--no-dns",
		fmt.Sprintf("-c%d", c.cycles),
	}
	if c.sourceIface != "" {
		// -I bind source interface
		args = append(args, "-I", c.sourceIface)
	}
	if c.sourceIP != "" {
		// -a bind source address
		args = append(args, "-a", c.sourceIP)
	}
	args = append(args, c.target)

	runCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, mtrPath, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Exit codes != 0 quando o target sumiu — emitimos available=1
			// para nao confundir com "binario ausente", mas perda=100.
			now := timestamppb.Now()
			return []*collectorv1.Metric{
				c.metric(now, "mtr.available", 1),
				c.metric(now, "mtr.hops", 0),
				c.metric(now, "mtr.last_hop_loss_pct", 100),
				c.metric(now, "mtr.last_hop_avg_ms", 0),
				c.metric(now, "mtr.worst_hop_loss_pct", 100),
			}, nil
		}
		// Timeout / outro erro fatal — sinaliza unavailable.
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "mtr.available", 0)}, nil
	}

	var report mtrReport
	if err := json.Unmarshal(out, &report); err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "mtr.available", 0)}, nil
	}

	hops := len(report.Report.Hubs)
	if hops == 0 {
		now := timestamppb.Now()
		return []*collectorv1.Metric{c.metric(now, "mtr.available", 1), c.metric(now, "mtr.hops", 0)}, nil
	}

	last := report.Report.Hubs[hops-1]
	worstLoss := 0.0
	// Pior hop intermediario (exclui o destino, mas inclui ele para hops=1).
	limit := hops - 1
	if limit < 1 {
		limit = 1
	}
	for i := 0; i < limit; i++ {
		if report.Report.Hubs[i].Loss > worstLoss {
			worstLoss = report.Report.Hubs[i].Loss
		}
	}

	now := timestamppb.Now()
	return []*collectorv1.Metric{
		c.metric(now, "mtr.available", 1),
		c.metric(now, "mtr.hops", float64(hops)),
		c.metric(now, "mtr.last_hop_loss_pct", last.Loss),
		c.metric(now, "mtr.last_hop_avg_ms", last.Avg),
		c.metric(now, "mtr.worst_hop_loss_pct", worstLoss),
	}, nil
}

func (c *mtrCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
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
		Source:     "mtr",
	}
}

func init() {
	Default.Register("mtr", newMTRCheck)
}
