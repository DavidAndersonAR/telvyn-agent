package checks

import (
	"context"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type stubCheck struct{ id string }

func (s *stubCheck) ID() string              { return s.id }
func (s *stubCheck) Interval() time.Duration { return 30 * time.Second }
func (s *stubCheck) Tags() map[string]string { return nil }
func (s *stubCheck) Run(_ context.Context) ([]*collectorv1.Metric, error) {
	return nil, nil
}

func newStubFactory(id string) Factory {
	return func(cfg *collectorv1.CheckConfig) (Check, error) {
		return &stubCheck{id: id}, nil
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	r.Register("stub", newStubFactory("a"))
	f, ok := r.Get("stub")
	if !ok || f == nil {
		t.Fatal("expected factory registered")
	}
	c, err := f(&collectorv1.CheckConfig{})
	if err != nil {
		t.Fatalf("factory err: %v", err)
	}
	if c.ID() != "a" {
		t.Errorf("got id=%q", c.ID())
	}
}

func TestRegistry_Get_Unknown_ReturnsFalse(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("expected ok=false for unknown type")
	}
}

func TestRegistry_Register_LastWins(t *testing.T) {
	r := NewRegistry()
	r.Register("foo", newStubFactory("first"))
	r.Register("foo", newStubFactory("second"))
	f, _ := r.Get("foo")
	c, _ := f(&collectorv1.CheckConfig{})
	if c.ID() != "second" {
		t.Errorf("expected last-wins, got %q", c.ID())
	}
}

func TestRegistry_Default_IsGlobal(t *testing.T) {
	if Default == nil {
		t.Fatal("Default is nil")
	}
	// Verifica que linux_system.init() ja registrou "linux.system":
	_, ok := Default.Get("linux.system")
	if !ok {
		t.Skip("linux.system not yet registered (run after Task 3)")
	}
}
