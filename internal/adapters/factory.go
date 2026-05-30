// Factory registry for server-driven adapter instantiation.
//
// Each adapter package registers a Factory under its canonical `kind` string
// in an init() — typically from a sibling factory.go in the adapter package.
// The collector main then imports those packages with a blank import to wire
// them in, and calls Build(kind, params, log) when a RegisterResponse arrives
// from the central server with adapters[].
//
// This keeps the agent decoupled from the wire format of params: each adapter
// owns its own param schema (extracted from a *structpb.Struct), so adding a
// new adapter is one new package + one blank import in main, no central edit.
package adapters

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"google.golang.org/protobuf/types/known/structpb"
)

// Factory builds a single Adapter instance from server-supplied params.
//
// `params` is the AdapterConfig.params field straight off the wire (proto
// Struct). Implementations are responsible for extracting and validating
// their own keys; missing required keys MUST return a descriptive error so
// the operator can fix the UI config without reading the agent source.
//
// `log` is the parent logger; factories typically attach an `adapter=<kind>`
// attribute before passing it to the adapter.
type Factory func(params *structpb.Struct, log *slog.Logger) (Adapter, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a factory under `kind`. Safe to call from init(); panics on
// duplicate registration since two factories for the same kind is always a
// programming error (would cause silent override on init order).
func Register(kind string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[kind]; exists {
		panic(fmt.Sprintf("adapters: duplicate Register for kind %q", kind))
	}
	registry[kind] = f
}

// Build looks up the factory for `kind` and constructs an adapter. Returns a
// descriptive error if the kind is unknown, listing the known kinds so the
// operator can correct the UI without grepping source.
func Build(kind string, params *structpb.Struct, log *slog.Logger) (Adapter, error) {
	registryMu.RLock()
	f, ok := registry[kind]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("adapters: unknown kind %q (known: %v)", kind, KnownKinds())
	}
	return f(params, log)
}

// KnownKinds returns the registered kinds in deterministic (sorted) order.
// Used in error messages and startup logs so operators can verify which
// adapters this agent build supports.
func KnownKinds() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
