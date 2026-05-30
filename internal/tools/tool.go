// Package tools holds the executors that run on the Collector when the
// central server pushes a ToolCommand via the reverse ToolChannel.
//
// Each executor implements a single tool (e.g. "ssh.exec") and returns a
// JSON-serializable result map. Credentials arrive in args and MUST NOT be
// persisted — the contract is "use in memory, discard, never write to disk".
//
// Anti-persistence guard: the Collector's Makefile runs
//   grep -rn "os\.WriteFile\|os\.Create" internal/tools/
// in CI to fail any regression that introduces a disk write here.
package tools

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/protobuf/types/known/structpb"
)

// Executor runs one tool. Implementations must be safe for concurrent use —
// the Collector may dispatch many ToolCommands in parallel.
type Executor interface {
	// Name is the canonical tool identifier ("ssh.exec", "snmp.get", ...).
	// Must match what's declared in RegisterRequest.capabilities so the
	// server can validate before dispatch.
	Name() string

	// Execute runs the tool. `args` is the args field of ToolCommand (proto Struct
	// converted to a Go map). Returns a structpb-friendly result that the
	// caller wraps into ToolResult.result.
	Execute(ctx context.Context, args map[string]any) (map[string]any, error)
}

// Registry holds the set of executors a Collector instance exposes.
type Registry struct {
	mu        sync.RWMutex
	executors map[string]Executor
}

func NewRegistry() *Registry {
	return &Registry{executors: map[string]Executor{}}
}

func (r *Registry) Register(e Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executors[e.Name()] = e
}

func (r *Registry) Get(name string) (Executor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.executors[name]
	return e, ok
}

// Names returns the canonical names of all registered executors. Used to
// populate RegisterRequest.capabilities at startup.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.executors))
	for n := range r.executors {
		names = append(names, n)
	}
	return names
}

// ToMap unwraps a structpb.Struct into a generic Go map. nil-safe.
func ToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return map[string]any{}
	}
	return s.AsMap()
}

// ToStruct wraps a Go map back into structpb.Struct for ToolResult.
func ToStruct(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

// ErrUnknownTool is returned by the dispatcher when a Collector receives a
// ToolCommand for a tool it doesn't expose. The server is supposed to
// pre-validate against capabilities, but defense in depth.
var ErrUnknownTool = errors.New("tool not registered on this collector")
