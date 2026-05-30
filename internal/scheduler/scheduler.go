// Package scheduler runs operator-defined ScheduledJobs at their configured
// cadence. Each job points at a registered Tool executor and an args bundle
// (target + credentials, resolved server-side); the scheduler ticks, invokes
// the tool, and converts the tool's structured result into wire Metrics
// pushed onto the same out-channel the (now legacy) adapters used.
//
// Lifecycle:
//   - Reload(jobs) cancels every running ticker and starts a fresh
//     generation. Same shape as adapterRuntime.Reload — the operator-facing
//     mental model is "swap the whole config", not "patch one job".
//   - Each generation owns a context derived from the parent; when Reload
//     replaces the generation, we cancel-and-wait so two ticks of the same
//     job never race.
//   - Disabled jobs are dropped at Reload time (not held in a paused state).
//   - interval_seconds <= 0 means "fire once at start of generation".
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ispwatch/collector/internal/tools"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// TopologySender é o callback usado pra forwardar TopologyEdgeReports
// extraídos de result["topology_edges"] via ReportTopology RPC. Mesmo
// shape do callback usado pelo runner LLDP-SNMP (transport.TopologySender)
// — quem cabea os dois é o main.go.
type TopologySender func(ctx context.Context, report *collectorv1.TopologyReport) (*collectorv1.TopologyAck, error)

type Runtime struct {
	parent   context.Context
	registry *tools.Registry
	out      chan<- []*collectorv1.Metric
	log      *slog.Logger

	mu       sync.Mutex
	cancel   context.CancelFunc
	wg       *sync.WaitGroup
	topoSink atomic.Pointer[TopologySender]
	batchSeq atomic.Int64
}

func New(parent context.Context, log *slog.Logger, registry *tools.Registry, out chan<- []*collectorv1.Metric) *Runtime {
	if log == nil {
		log = slog.Default()
	}
	return &Runtime{
		parent:   parent,
		registry: registry,
		out:      out,
		log:      log.With("component", "scheduler"),
	}
}

// ReloadServerDriven is the entrypoint for server-delivered job sets
// (transport.OnScheduledJobs). It implements KEEP-CURRENT-ON-EMPTY: a NEW,
// non-empty generation swaps the running set; an EMPTY generation is treated
// as "server has no opinion / transient empty during a backend restart" and
// the current job set is LEFT RUNNING so polling never stops (Task 2).
//
// Rationale: the wire protocol carries no generation number or explicit
// "zero jobs" flag, so a transient empty (Quarkus mid-restart) is
// indistinguishable from an intentional clear. We default to keep-current and
// log loudly. Use Reload(nil) directly for an intentional teardown (shutdown).
func (r *Runtime) ReloadServerDriven(jobs []*collectorv1.ScheduledJob) {
	if len(jobs) == 0 {
		r.log.Warn("scheduler: empty job generation from server — KEEPING current jobs running (keep-current-on-empty; wire has no intentional-empty flag)")
		return
	}
	r.Reload(jobs)
}

// Reload swaps the running job set. Empty list cancels everything — this is an
// INTENTIONAL teardown (used on shutdown). Server-driven paths must call
// ReloadServerDriven instead so a transient empty generation does not stop
// collection.
func (r *Runtime) Reload(jobs []*collectorv1.ScheduledJob) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Tear the previous generation down deterministically.
	if r.cancel != nil {
		r.cancel()
		if r.wg != nil {
			r.wg.Wait()
		}
		r.cancel = nil
		r.wg = nil
	}

	if len(jobs) == 0 {
		r.log.Info("scheduler reload: no jobs in generation")
		return
	}

	enabled := 0
	for _, j := range jobs {
		if j.GetEnabled() {
			enabled++
		}
	}
	r.log.Info("scheduler reload",
		"jobs_total", len(jobs),
		"jobs_enabled", enabled)

	ctx, cancel := context.WithCancel(r.parent)
	wg := &sync.WaitGroup{}
	for _, j := range jobs {
		if !j.GetEnabled() {
			continue
		}
		exec, ok := r.registry.Get(j.GetTool())
		if !ok {
			r.log.Warn("scheduler skipping job — unknown tool",
				"job_id", j.GetJobId(), "tool", j.GetTool())
			continue
		}
		wg.Add(1)
		go r.runJob(ctx, wg, j, exec)
	}
	r.cancel = cancel
	r.wg = wg
}

// runJob is the per-job goroutine: fire once immediately, then on each tick.
// "Once at start" semantics keep dashboards from waiting a full interval for
// first data on a freshly-applied config.
func (r *Runtime) runJob(ctx context.Context, wg *sync.WaitGroup, j *collectorv1.ScheduledJob, exec tools.Executor) {
	defer wg.Done()
	jlog := r.log.With("job_id", j.GetJobId(), "tool", j.GetTool(), "host_id", j.GetHostId())
	jlog.Info("scheduler job starting")

	r.fireOnce(ctx, jlog, j, exec)

	if j.GetIntervalSeconds() <= 0 {
		jlog.Info("scheduler job exiting — interval<=0 means run-once")
		return
	}
	t := time.NewTicker(time.Duration(j.GetIntervalSeconds()) * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			jlog.Info("scheduler job stopping")
			return
		case <-t.C:
			r.fireOnce(ctx, jlog, j, exec)
		}
	}
}

// SetTopologySender swaps the active sender atomically. Called by main.go
// on each successful Register (transport.OnTopologySender) so reconnects
// keep working without restarting the scheduler.
func (r *Runtime) SetTopologySender(s TopologySender) {
	r.topoSink.Store(&s)
}

// fireOnce executes the tool and emits whatever metrics it produced. Errors
// are logged at WARN — a single failed tick should never crash the runtime,
// because operators expect "the box is unreachable for a minute" to recover
// silently on the next tick.
func (r *Runtime) fireOnce(ctx context.Context, log *slog.Logger, j *collectorv1.ScheduledJob, exec tools.Executor) {
	args := tools.ToMap(j.GetArgs())
	res, err := exec.Execute(ctx, args)
	if err != nil {
		log.Warn("scheduler tool execution failed", "err", err)
		return
	}
	metrics := metricsFromResult(j.GetHostId(), res)
	if len(metrics) > 0 {
		select {
		case r.out <- metrics:
			log.Debug("scheduler emitted metrics", "count", len(metrics))
		case <-ctx.Done():
			return
		}
	}

	// Topology path: tools como mikrotik.discover_topology populam
	// result["topology_edges"]. O scheduler dispara ReportTopology com o
	// batch consolidado num único RPC — Quarkus persiste em /topology/discovery
	// no Django.
	edges := topologyEdgesFromResult(res)
	if len(edges) > 0 {
		// Loga metadados ricos do tool pra debug (source_counts, etc.)
		extra := []any{"edges_total", len(edges)}
		if v, ok := res["source_counts"].(map[string]any); ok {
			for k, val := range v {
				extra = append(extra, "src_"+k, val)
			}
		}
		if v, ok := res["self_loops_dropped"].(float64); ok {
			extra = append(extra, "self_loops_dropped", v)
		}
		if v, ok := res["deduped_dropped"].(float64); ok {
			extra = append(extra, "deduped", v)
		}
		if v, ok := res["local_identity"].(string); ok {
			extra = append(extra, "local_identity", v)
		}
		log.Info("scheduler discovery sources", extra...)
		r.sendTopology(ctx, log, edges)
	}

	if len(metrics) == 0 && len(edges) == 0 {
		log.Debug("scheduler tool returned no metrics or topology", "result_keys", keys(res))
	}
}

// sendTopology constrói um TopologyReport e envia via Sender. Sender ausente
// (transport ainda não conectou) descarta o ciclo com WARN — próximo tick
// tenta de novo com dados frescos.
func (r *Runtime) sendTopology(ctx context.Context, log *slog.Logger, edges []*collectorv1.TopologyEdgeReport) {
	sp := r.topoSink.Load()
	if sp == nil {
		log.Warn("scheduler dropped topology — sender not set yet (transport not ready)",
			"edges", len(edges))
		return
	}
	send := *sp

	report := &collectorv1.TopologyReport{
		BatchSeq:  r.batchSeq.Add(1),
		ScannedAt: timestamppb.Now(),
		Edges:     edges,
	}
	postCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ack, err := send(postCtx, report)
	if err != nil {
		log.Warn("scheduler topology send failed", "edges", len(edges), "err", err)
		return
	}
	log.Info("scheduler topology sent",
		"edges_received", ack.GetEdgesReceived(),
		"edges_persisted", ack.GetEdgesPersisted(),
		"edges_unmatched", ack.GetEdgesUnmatched(),
	)
}

// topologyEdgesFromResult espelha metricsFromResult: extrai
// result["topology_edges"] (lista de map[string]any) e converte cada entry
// num TopologyEdgeReport. Entradas com formato inválido são descartadas
// silenciosamente — não derruba o tick por causa de uma malformada.
func topologyEdgesFromResult(res map[string]any) []*collectorv1.TopologyEdgeReport {
	raw, ok := res["topology_edges"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		// Tools podem devolver []map[string]any direto — tenta o cast também
		if direct, ok := raw.([]map[string]any); ok {
			list = make([]any, len(direct))
			for i, m := range direct {
				list[i] = m
			}
		} else {
			return nil
		}
	}
	out := make([]*collectorv1.TopologyEdgeReport, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		edge := buildTopologyEdgeReport(m)
		if edge != nil {
			out = append(out, edge)
		}
	}
	return out
}

func buildTopologyEdgeReport(m map[string]any) *collectorv1.TopologyEdgeReport {
	localHostId, _ := m["local_host_id"].(string)
	if localHostId == "" {
		return nil
	}
	e := &collectorv1.TopologyEdgeReport{
		LocalHostId:    localHostId,
		LocalIface:     stringFromMap(m, "local_iface"),
		RemoteChassisId: stringFromMap(m, "remote_chassis_id"),
		RemotePortId:    stringFromMap(m, "remote_port_id"),
		RemotePortDesc:  stringFromMap(m, "remote_port_desc"),
		RemoteSysName:   stringFromMap(m, "remote_sys_name"),
		RemoteSysDescr:  stringFromMap(m, "remote_sys_descr"),
		Layer:           stringFromMap(m, "layer"),
		SourceProtocol:  stringFromMap(m, "source_protocol"),
		LinkType:        stringFromMap(m, "link_type"),
	}
	if v, ok := numericValue(m["local_iface_speed_mbps"]); ok {
		e.LocalIfaceSpeedMbps = int32(v)
	}
	if v, ok := numericValue(m["remote_chassis_id_subtype"]); ok {
		e.RemoteChassisIdSubtype = int32(v)
	}
	if v, ok := numericValue(m["remote_port_id_subtype"]); ok {
		e.RemotePortIdSubtype = int32(v)
	}
	// raw payload pra debug (pra UI mostrar campos vendor-específicos do
	// equipamento descoberto). Tools devolvem map[string]any; convertemos
	// pra structpb. Erro de conversão é não-fatal: edge ainda tem o resto.
	if rawAny, ok := m["raw"].(map[string]any); ok && len(rawAny) > 0 {
		if rawStruct, err := structpb.NewStruct(rawAny); err == nil {
			e.Raw = rawStruct
		}
	}
	if e.Layer == "" {
		e.Layer = "L2"
	}
	if e.SourceProtocol == "" {
		e.SourceProtocol = "lldp"
	}
	return e
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// metricsFromResult is the contract between Tool executors and the wire:
// a tool that wants its outputs persisted as time-series MUST set
//
//	result["metrics"] = []map{ {name, value, source?, interface_name?,
//	                            peer_id?, tags?}, ... }
//
// Anything else in result is ignored by the scheduler (it may still be
// useful in ToolChannel responses for ad-hoc IA queries). Per-metric host_id
// defaults to the job's host_id; emitted_at defaults to "now".
func metricsFromResult(defaultHostID string, res map[string]any) []*collectorv1.Metric {
	raw, ok := res["metrics"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	now := timestamppb.New(time.Now())
	out := make([]*collectorv1.Metric, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		val, ok := numericValue(m["value"])
		if !ok {
			continue
		}
		metric := &collectorv1.Metric{
			Time:       now,
			HostId:     defaultHostID,
			MetricName: name,
			Value:      val,
		}
		if hostOverride, ok := m["host_id"].(string); ok && hostOverride != "" {
			metric.HostId = hostOverride
		}
		if iface, ok := m["interface_name"].(string); ok {
			metric.InterfaceName = iface
		}
		if peer, ok := m["peer_id"].(string); ok {
			metric.PeerId = peer
		}
		if src, ok := m["source"].(string); ok {
			metric.Source = src
		}
		if tagsRaw, ok := m["tags"].(map[string]any); ok && len(tagsRaw) > 0 {
			tags := make(map[string]string, len(tagsRaw))
			for k, v := range tagsRaw {
				switch s := v.(type) {
				case string:
					tags[k] = s
				default:
					tags[k] = fmt.Sprintf("%v", s)
				}
			}
			metric.Tags = tags
		}
		out = append(out, metric)
	}
	return out
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
