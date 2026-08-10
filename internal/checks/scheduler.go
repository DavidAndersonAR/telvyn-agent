// Package checks — Runtime schedules and manages the active check goroutines.
//
// checks.Runtime mirrors the shape of scheduler.Runtime (internal/scheduler):
//   - Reload([]*CheckConfig) swaps the whole generation atomically:
//     cancel previous generation + wait (deterministic), then start new one.
//   - One goroutine per check ("once-at-start" + ticker).
//   - Disabled checks are dropped at Reload time (not held in paused state).
//   - Circuit-break after circuitBreakThreshold consecutive errors — prevents
//     a broken check from spam-logging on every tick.
//   - Meta-metric "ispwatch.check.errors{check_id}" emitted on Run() error.
package checks

import (
	"context"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// circuitBreakThreshold is the number of consecutive errors before a check
// is circuit-broken (Run() calls are skipped until a successful run resets
// the counter).
const circuitBreakThreshold = int32(5)

const (
	defaultGenerationStopTimeout = 10 * time.Second
	defaultMinCheckRunTimeout    = 15 * time.Second
	defaultMaxCheckRunTimeout    = 2 * time.Minute
)

// Runtime owns the active set of checks and a per-check goroutine pool.
//
// Phase 5: passou a operar tanto no modo legado Reload(geração inteira) quanto
// no modo pull-delta ApplyDelta(added, deleted) — este último mantém checks
// inalterados rodando, evitando o "stop all → start all" que estourava o
// timeout sob carga.
type Runtime struct {
	parent   context.Context
	registry *Registry
	out      chan<- []*collectorv1.Metric
	log      *slog.Logger

	reloadMu sync.Mutex
	mu       sync.Mutex
	cancel   context.CancelFunc
	wg       *sync.WaitGroup

	stopTimeout   time.Duration
	minRunTimeout time.Duration
	maxRunTimeout time.Duration

	// Phase 5 — tracking per-check pra ApplyDelta. Cada check tem o próprio
	// cancel + waitgroup; ApplyDelta cancela só os deletados e arranca só os
	// novos, deixando o resto rodando.
	checksMu sync.Mutex
	checks   map[string]*runningCheck // checkID → handle

	// Worker pool semaphores: limitam concorrência por kind (snmp, icmp).
	// Setados via SetWorkerPools durante o startup. nil = sem limite.
	snmpSem chan struct{}
	icmpSem chan struct{}
	// Jitter máximo (ms) aplicado no primeiro tick de cada check pra
	// espalhar walks pesados que ficariam todos no segundo 0.
	jitterMs int

	// tagger é o middleware de cardinality budget (Phase 3 Plan 4). Setado
	// via SetTagger durante o startup do main; nil em testes legados — emit
	// faz defensive nil-check para preservar comportamento Phase 2.
	tagger *Tagger

	// statusReporter leva o MOTIVO da falha pro backend. Até então o motivo
	// morria no log local: a tela do equipamento mostrava "warning" e quem
	// quisesse saber por quê precisava de SSH na máquina do cliente. nil =
	// ninguém reporta (testes, modo mTLS legado).
	statusReporter StatusReporter
}

// StatusReporter recebe o estado de um check quando ele MUDA (passou a falhar,
// voltou a funcionar, ou a mensagem de erro mudou). Não é chamado a cada tick:
// um agente com 50 checks quebrados viraria 50 POSTs por minuto sem novidade
// nenhuma — "desde quando" o backend calcula sozinho.
type StatusReporter func(checkID string, ok bool, message string)

// runningCheck guarda o estado de uma check rodando: cancel pra parar e wg
// pra esperar conclusão graciosa.
type runningCheck struct {
	cancel context.CancelFunc
	done   chan struct{}
	cfgVer int64 // config_version do servidor — pra detectar updates idempotentes
}

// SetWorkerPools configura os semáforos de concorrência. Chamar antes de
// Reload/ApplyDelta. snmp/icmp = 0 desliga o limite (run unbounded).
func (r *Runtime) SetWorkerPools(snmp, icmp int) {
	if snmp > 0 { r.snmpSem = make(chan struct{}, snmp) }
	if icmp > 0 { r.icmpSem = make(chan struct{}, icmp) }
}

// SetJitter define o jitter máximo em ms aplicado no primeiro tick.
func (r *Runtime) SetJitter(jitterMs int) {
	if jitterMs > 0 { r.jitterMs = jitterMs }
}

// New creates a checks.Runtime. log and registry may be nil — defaults are
// applied (slog.Default() and Default registry respectively).
func New(parent context.Context, log *slog.Logger, registry *Registry, out chan<- []*collectorv1.Metric) *Runtime {
	if log == nil {
		log = slog.Default()
	}
	if registry == nil {
		registry = Default
	}
	return &Runtime{
		parent:        parent,
		registry:      registry,
		out:           out,
		log:           log.With("component", "checks"),
		stopTimeout:   defaultGenerationStopTimeout,
		minRunTimeout: defaultMinCheckRunTimeout,
		maxRunTimeout: defaultMaxCheckRunTimeout,
		checks:        make(map[string]*runningCheck),
	}
}

// ApplyDelta atualiza incrementalmente o set de checks rodando:
//   - added: cria goroutines pra esses (ou substitui se ID já existir, na
//     pratica vindo do server com config_version maior).
//   - deletedIDs: cancela e remove esses do scheduler.
//
// Diferente de Reload, NÃO toca em checks que não estão em nenhuma das duas
// listas. Aderente ao protocolo pull/delta (Phase 5).
func (r *Runtime) ApplyDelta(added []*collectorv1.CheckConfig, deletedIDs []string) (addedCount, removedCount int) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	// 1) Remove deletados
	for _, id := range deletedIDs {
		if r.stopCheck(id) {
			removedCount++
		}
	}
	// 2) Adiciona/atualiza
	for _, cfg := range added {
		if !cfg.GetEnabled() {
			// disabled = remove se estava rodando
			if r.stopCheck(cfg.GetCheckId()) {
				removedCount++
			}
			continue
		}
		factory, ok := r.registry.Get(cfg.GetCheckType())
		if !ok {
			r.log.Warn("checks delta: unknown check_type",
				"check_id", cfg.GetCheckId(), "check_type", cfg.GetCheckType())
			continue
		}
		check, err := factory(cfg)
		if err != nil {
			r.log.Warn("checks delta: factory error",
				"check_id", cfg.GetCheckId(), "err", err)
			continue
		}
		// Se já tem rodando, para e substitui (update = stop + start novo)
		r.stopCheck(cfg.GetCheckId())
		r.startCheck(check)
		addedCount++
	}
	r.log.Info("checks delta applied",
		"added_or_updated", addedCount, "removed", removedCount,
		"total_running", r.countRunning())
	return addedCount, removedCount
}

// startCheck arranca uma nova goroutine pra check; assume reloadMu held.
func (r *Runtime) startCheck(c Check) {
	if r.parent == nil { return }
	ctx, cancel := context.WithCancel(r.parent)
	done := make(chan struct{})
	rc := &runningCheck{cancel: cancel, done: done}
	r.checksMu.Lock()
	r.checks[c.ID()] = rc
	r.checksMu.Unlock()
	go func() {
		defer close(done)
		r.runOneCheck(ctx, c)
	}()
}

// stopCheck cancela e aguarda check com o id dado; retorna true se existia.
func (r *Runtime) stopCheck(id string) bool {
	r.checksMu.Lock()
	rc, ok := r.checks[id]
	if ok { delete(r.checks, id) }
	r.checksMu.Unlock()
	if !ok { return false }
	rc.cancel()
	select {
	case <-rc.done:
	case <-time.After(r.stopTimeout):
		r.log.Warn("checks delta: stop timeout", "check_id", id)
	}
	return true
}

func (r *Runtime) countRunning() int {
	r.checksMu.Lock(); defer r.checksMu.Unlock()
	return len(r.checks)
}

// ReloadServerDriven is the entrypoint for server-delivered check sets
// (config.reload push). It implements KEEP-CURRENT-ON-EMPTY: a NEW, non-empty
// generation swaps the running set; an EMPTY generation is treated as "server
// has no opinion / transient empty during a backend restart" and the current
// check set is LEFT RUNNING so polling never stops (Task 2).
//
// Rationale: the config.reload wire carries no generation number or explicit
// "zero checks" flag, so a transient empty (Quarkus mid-restart) is
// indistinguishable from an intentional clear. We default to keep-current and
// log loudly. The pull path (configpull → ApplyDelta) already preserves
// unchanged checks via deltas, so it does not route through here. Use
// Reload(nil) directly for an intentional teardown (shutdown).
func (r *Runtime) ReloadServerDriven(cfgs []*collectorv1.CheckConfig) {
	if len(cfgs) == 0 {
		r.log.Warn("checks: empty check generation from server — KEEPING current checks running (keep-current-on-empty; wire has no intentional-empty flag)")
		return
	}
	r.Reload(cfgs)
}

// Reload swaps the running check set. Empty list (or nil) cancels everything —
// this is an INTENTIONAL teardown (used on shutdown). Server-driven paths must
// call ReloadServerDriven instead so a transient empty generation does not stop
// collection.
// It waits for the previous generation outside the emit mutex so canceled
// checks can finish and emit/drop cleanly without deadlocking config.reload.
func (r *Runtime) Reload(cfgs []*collectorv1.CheckConfig) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	r.stopCurrentGeneration()

	if len(cfgs) == 0 {
		r.log.Info("checks reload: no checks in generation")
		return
	}

	enabled := 0
	for _, c := range cfgs {
		if c.GetEnabled() {
			enabled++
		}
	}
	r.log.Info("checks reload",
		"checks_total", len(cfgs),
		"checks_enabled", enabled)

	ctx, cancel := context.WithCancel(r.parent)
	wg := &sync.WaitGroup{}
	for _, cfg := range cfgs {
		if !cfg.GetEnabled() {
			continue
		}
		factory, ok := r.registry.Get(cfg.GetCheckType())
		if !ok {
			r.log.Warn("checks skipping cfg — unknown check_type",
				"check_id", cfg.GetCheckId(),
				"check_type", cfg.GetCheckType())
			continue
		}
		check, err := factory(cfg)
		if err != nil {
			r.log.Warn("checks skipping cfg — factory error",
				"check_id", cfg.GetCheckId(),
				"check_type", cfg.GetCheckType(),
				"err", err)
			continue
		}
		wg.Add(1)
		go r.runCheck(ctx, wg, check)
	}
	r.mu.Lock()
	r.cancel = cancel
	r.wg = wg
	r.mu.Unlock()
}

func (r *Runtime) stopCurrentGeneration() {
	r.mu.Lock()
	cancel := r.cancel
	wg := r.wg
	r.cancel = nil
	r.wg = nil
	r.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if wg == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	timeout := r.stopTimeout
	if timeout <= 0 {
		timeout = defaultGenerationStopTimeout
	}
	select {
	case <-done:
	case <-time.After(timeout):
		r.log.Warn("checks reload: previous generation still stopping; continuing with new generation",
			"timeout", timeout.String())
	}
}

// runCheck (legado): variante com WaitGroup compartilhado, usada por Reload.
// Apenas delega pro core compartilhado.
func (r *Runtime) runCheck(ctx context.Context, wg *sync.WaitGroup, c Check) {
	defer wg.Done()
	r.runCheckCore(ctx, c)
}

// runOneCheck (Phase 5): variante per-check usada pelo ApplyDelta.
// Sem WaitGroup compartilhado — quem chama controla o ciclo via stopCheck.
func (r *Runtime) runOneCheck(ctx context.Context, c Check) {
	r.runCheckCore(ctx, c)
}

// runCheckCore é o loop de execução compartilhado:
//   - jitter inicial (0..jitterMs) pra espalhar walks pesados
//   - worker pool acquire por kind (snmp.* / icmp.*) limita concorrência
//   - once-at-start, depois ticker
//   - timeout per-run, circuit-break por N erros consecutivos
func (r *Runtime) runCheckCore(ctx context.Context, c Check) {
	clog := r.log.With("check_id", c.ID())

	interval := c.Interval()
	if interval <= 0 {
		clog.Warn("checks: interval <= 0, defaulting to 30s")
		interval = 30 * time.Second
	}

	// Jitter: aplica um delay aleatório pra que checks criados em ondas
	// (e.g. 100 hosts criados em sequência) não disparem todos no mesmo
	// instante. Crítico pra SNMP walks pesados.
	if r.jitterMs > 0 {
		delay := time.Duration(rand.Intn(r.jitterMs)) * time.Millisecond
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var consecutiveErrors atomic.Int32
	runTimeout := r.runTimeout(interval)

	// Seleciona o semáforo de worker pool de acordo com o kind.
	var sem chan struct{}
	if c, ok := any(c).(interface{ Kind() string }); ok {
		switch c.Kind() {
		case "snmp": sem = r.snmpSem
		case "icmp": sem = r.icmpSem
		}
	}
	// Fallback: detecta pelo prefixo do ID (mais frouxo).
	if sem == nil {
		switch {
		case startsWith(c.ID(), "snmp."): sem = r.snmpSem
		case startsWith(c.ID(), "icmp."): sem = r.icmpSem
		}
	}

	// Estado do último reporte deste check. Fica na closure porque cada check
	// tem sua própria goroutine — sem lock nem mapa compartilhado.
	var reportadoOK *bool
	var reportadaMsg string
	reportar := func(ok bool, msg string) {
		if reportadoOK != nil && *reportadoOK == ok && reportadaMsg == msg {
			return // nada mudou: não repete
		}
		v := ok
		reportadoOK, reportadaMsg = &v, msg
		r.reportStatus(c.ID(), ok, msg)
	}

	runOnce := func() {
		if consecutiveErrors.Load() >= circuitBreakThreshold {
			clog.Debug("circuit-break active, skipping tick")
			return
		}
		// Worker pool: serializa N execuções concorrentes do mesmo kind.
		if sem != nil {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
		}
		runCtx, cancel := context.WithTimeout(ctx, runTimeout)
		metrics, err := c.Run(runCtx)
		runErr := runCtx.Err()
		cancel()

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			n := consecutiveErrors.Add(1)
			clog.Warn("check run error", "err", err, "consecutive", n, "run_timeout", runTimeout.String())
			r.emitCheckError(c)
			reportar(false, err.Error())
			return
		}
		if runErr == context.DeadlineExceeded {
			n := consecutiveErrors.Add(1)
			clog.Warn("check run exceeded timeout", "consecutive", n, "run_timeout", runTimeout.String())
			r.emitCheckError(c)
			reportar(false, "sem resposta em "+runTimeout.String())
			return
		}
		consecutiveErrors.Store(0)
		reportar(true, "")
		if len(metrics) > 0 {
			r.emit(metrics)
		}
	}

	runOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func (r *Runtime) runTimeout(interval time.Duration) time.Duration {
	timeout := interval * 2
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	minTimeout := r.minRunTimeout
	if minTimeout <= 0 {
		minTimeout = defaultMinCheckRunTimeout
	}
	maxTimeout := r.maxRunTimeout
	if maxTimeout <= 0 {
		maxTimeout = defaultMaxCheckRunTimeout
	}
	if timeout < minTimeout {
		return minTimeout
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

// SetStatusReporter instala quem leva o motivo da falha pro backend. Idempotente;
// nil reverte pra ninguém. Setar no startup, antes de Reload/ApplyDelta.
func (r *Runtime) SetStatusReporter(f StatusReporter) {
	r.mu.Lock()
	r.statusReporter = f
	r.mu.Unlock()
}

func (r *Runtime) reportStatus(checkID string, ok bool, message string) {
	r.mu.Lock()
	f := r.statusReporter
	r.mu.Unlock()
	if f == nil {
		return
	}
	f(checkID, ok, message)
}

func (r *Runtime) emitCheckError(c Check) {
	r.emit([]*collectorv1.Metric{{
		Time:       timestamppb.Now(),
		MetricName: "ispwatch.check.errors",
		Value:      1.0,
		Tags:       map[string]string{"check_id": c.ID()},
		Source:     "checks",
	}})
}

// SetTagger instala o middleware de cardinality budget. Idempotente; setar
// nil reverte para passthrough. Pode ser chamado a qualquer momento (lock
// curto). A leitura em emit é não-locada porque ponteiros de palavra-única
// em Go são lidos atomicamente em práticas — single-writer (startup) +
// many-readers (per-tick) é seguro nesse padrão.
func (r *Runtime) SetTagger(t *Tagger) {
	r.mu.Lock()
	r.tagger = t
	r.mu.Unlock()
}

// emit sends a batch of metrics to the out channel. Non-blocking: drops with
// a WARN if the channel is full (backpressure relief — same pattern as the
// scheduler; consumer is transport.StreamMetrics which is normally fast).
//
// Phase 3 Plan 4: when a tagger is installed, emit interpõe Filter antes do
// canal. Séries acima do budget per-host viram meta-métricas
// `ispwatch.tagger.dropped` que viajam no mesmo batch (fast-path no Filter
// garante que elas próprias não sejam dropadas — Pitfall 4 do RESEARCH).
func (r *Runtime) emit(metrics []*collectorv1.Metric) {
	r.mu.Lock()
	tagger := r.tagger
	r.mu.Unlock()

	if tagger != nil {
		kept, drops := tagger.Filter(metrics)
		if len(drops) > 0 {
			kept = append(kept, drops...)
		}
		metrics = kept
	}
	if len(metrics) == 0 {
		return
	}
	select {
	case r.out <- metrics:
	default:
		r.log.Warn("checks: out channel full, dropping batch", "count", len(metrics))
	}
}
