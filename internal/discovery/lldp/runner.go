package lldp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Sender envia um TopologyReport ao servidor central. Implementação real
// vive em internal/transport (ReportTopology RPC); o runner não conhece
// gRPC pra ficar testável.
type Sender func(ctx context.Context, report *collectorv1.TopologyReport) (*collectorv1.TopologyAck, error)

// Target é um equipamento que será scaneado periodicamente.
type Target struct {
	HostId    string  // identidade do host no inventário do servidor
	Address   string  // "host" ou "host:port" SNMP
	Community string
}

// Options configura o runner. Interval == 0 desliga.
type Options struct {
	CollectorId string
	Targets     []Target
	Interval    time.Duration
	Timeout     time.Duration  // por target SNMP
}

// ClientFactory cria um SnmpClient pra um target. Permite injetar
// implementação de teste sem importar gosnmp aqui.
type ClientFactory func(target, community string, timeout time.Duration) SnmpClient

// Runner orquestra o ciclo: tickea, faz walk em N targets em paralelo,
// junta tudo num único TopologyReport por ciclo, envia.
type Runner struct {
	opts    Options
	log     *slog.Logger
	build   ClientFactory
	sender  atomic.Pointer[Sender]
	mu      sync.Mutex
	batchSeq int64
}

func NewRunner(opts Options, log *slog.Logger, build ClientFactory) *Runner {
	return &Runner{opts: opts, log: log, build: build}
}

// SetSender troca o sender em runtime. Necessário porque o sender só fica
// válido depois que o transport completou o Register no servidor central.
func (r *Runner) SetSender(s Sender) {
	r.sender.Store(&s)
}

// Run blocks until ctx is cancelled. Tickea no intervalo configurado e
// chama RunOnce a cada tick. Loga e segue em caso de erro — discovery
// individual não derruba o runner.
func (r *Runner) Run(ctx context.Context) error {
	if r.opts.Interval <= 0 {
		r.log.Info("lldp runner disabled (interval=0)")
		return nil
	}
	if len(r.opts.Targets) == 0 {
		r.log.Info("lldp runner has no targets, exiting")
		return nil
	}

	t := time.NewTicker(r.opts.Interval)
	defer t.Stop()

	// Primeiro scan imediato pra evitar esperar 1 intervalo inteiro.
	r.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce executa um ciclo: para cada target paralelo, faz walk e junta no
// mesmo report. Sender ausente ainda? Loga warn e descarta o ciclo.
func (r *Runner) runOnce(ctx context.Context) {
	sp := r.sender.Load()
	if sp == nil {
		r.log.Warn("lldp tick skipped: sender not set yet (transport not ready)")
		return
	}
	sender := *sp

	timeout := r.opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout*time.Duration(len(r.opts.Targets)+1))
	defer cancel()

	type scanResult struct {
		target  string
		edges   []*collectorv1.TopologyEdgeReport
		err     error
	}
	resultCh := make(chan scanResult, len(r.opts.Targets))

	for _, tgt := range r.opts.Targets {
		tgt := tgt // capture
		go func() {
			c := r.build(tgt.Address, tgt.Community, timeout)
			defer c.Close()
			edges, err := Walk(scanCtx, c, tgt.HostId)
			resultCh <- scanResult{target: tgt.Address, edges: edges, err: err}
		}()
	}

	all := make([]*collectorv1.TopologyEdgeReport, 0)
	for i := 0; i < len(r.opts.Targets); i++ {
		res := <-resultCh
		if res.err != nil {
			r.log.Warn("lldp walk failed", "target", res.target, "err", res.err)
			continue
		}
		r.log.Debug("lldp walk ok", "target", res.target, "edges", len(res.edges))
		all = append(all, res.edges...)
	}

	if len(all) == 0 {
		r.log.Info("lldp cycle: no edges discovered")
		return
	}

	r.mu.Lock()
	r.batchSeq++
	seq := r.batchSeq
	r.mu.Unlock()

	report := &collectorv1.TopologyReport{
		CollectorId: r.opts.CollectorId,
		BatchSeq:    seq,
		ScannedAt:   timestamppb.Now(),
		Edges:       all,
	}

	postCtx, postCancel := context.WithTimeout(ctx, 15*time.Second)
	defer postCancel()
	ack, err := sender(postCtx, report)
	if err != nil {
		r.log.Error("lldp report failed", "edges", len(all), "err", err)
		return
	}
	r.log.Info("lldp report sent",
		"edges_received", ack.GetEdgesReceived(),
		"edges_persisted", ack.GetEdgesPersisted(),
		"edges_unmatched", ack.GetEdgesUnmatched(),
		"batch_seq", seq,
	)
}

// Format helper used in tests
func (o Options) String() string {
	return fmt.Sprintf("LLDP{targets=%d interval=%s}", len(o.Targets), o.Interval)
}
