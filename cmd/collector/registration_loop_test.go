package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectorRegistrationLoopRecoversAfterTransientStartupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	registered := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCollectorRegistrationLoop(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
			time.Millisecond, 5*time.Millisecond,
			func(context.Context) (string, string, error) {
				if attempts.Add(1) < 3 {
					return "", "", errors.New("backend unavailable")
				}
				return "collector-id", "tenant-id", nil
			},
			func(collectorID, tenantID string) {
				if collectorID != "collector-id" || tenantID != "tenant-id" {
					t.Errorf("unexpected identity: %q %q", collectorID, tenantID)
				}
				registered <- struct{}{}
			})
	}()

	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("registration did not recover")
	}

	deadline := time.After(time.Second)
	for attempts.Load() < 4 {
		select {
		case <-deadline:
			t.Fatal("heartbeat did not run after registration recovery")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("registration loop did not stop on context cancellation")
	}
}
