// Package checks defines the continuous self-metric collection framework
// for the IspWatch agent. A Check runs in-process at a fixed cadence and
// emits Metrics about the host where the agent is installed (Local Agent
// mode per D-12) or the device it polls (Collector mode).
//
// Lifecycle parallels tools/scheduler:
//   - Each Check is registered at init() time against a string check_type.
//   - Runtime.Reload([]*CheckConfig) instantiates new Check instances per
//     config entry and swaps the running generation deterministically
//     (cancel-and-wait, same semantic as scheduler.Runtime.Reload).
//   - Checks are run as 1 goroutine per check (no pool — checks are
//     expected to be <100ms each; pool would just add complexity).
//
// Plan 4 ships the framework + `linux.system` (system metrics from /proc
// and /sys via gopsutil v4). Phase 3+ adds SNMP/Windows/Mikrotik/ICMP
// checks; Phase 4 adds application checks (postgres, nginx, etc.)
// composed via template_id.
package checks

import (
	"context"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Check is the interface implemented by every continuous metric collector
// in the agent. Run is expected to complete within Interval() — if it
// takes longer the next tick is skipped (scheduler skips, doesn't queue).
type Check interface {
	// ID returns a stable identifier used for log correlation and error
	// metrics. Convention: "<check_type>-<host_id>" or operator-supplied.
	ID() string

	// Interval returns the run cadence. Must be > 0.
	Interval() time.Duration

	// Tags returns static k=v tags applied to every metric emitted by
	// this check. Includes static_tags from CheckConfig.
	Tags() map[string]string

	// Run executes one sampling cycle. Must respect ctx.Done() — Reload
	// cancels ctx during shutdown. Returns metrics + error; non-nil error
	// increments the check_errors counter and may trip circuit-break.
	Run(ctx context.Context) ([]*collectorv1.Metric, error)
}

// Factory constructs a Check instance from a CheckConfig. Returning an
// error fails the Reload silently (the offending check is logged and
// skipped — other checks in the generation still start). Idiomatic
// factories validate Params and StaticTags here.
type Factory func(cfg *collectorv1.CheckConfig) (Check, error)

// Registry maps check_type strings to Factory functions. Mirrors the
// shape of tools.Registry. Thread-safe.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Factory
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]Factory{}}
}

// Register associates check_type with a Factory. Last-wins semantics —
// re-registering a type with a new Factory swaps the entry (matches the
// mental model of "init() ordering doesn't matter; the package that loads
// last wins"). Tests reset Default between cases by allocating fresh.
func (r *Registry) Register(checkType string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[checkType] = f
}

// Get looks up a Factory by check_type. ok=false when unregistered.
func (r *Registry) Get(checkType string) (Factory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.entries[checkType]
	return f, ok
}

// Default is the package-level registry. linux.system auto-registers
// here in linux_system.go init(); main.go consults Default.
var Default = NewRegistry()
