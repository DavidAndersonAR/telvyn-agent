// Package configcache persists the last-known-good server-driven config to
// disk so the collector can keep running its jobs across a backend restart or
// a multi-hour POP isolation — like a remote proxy caching its config (Task 2,
// config/job continuity).
//
// What is cached: the full CollectorConfig proto from the most recent
// NON-EMPTY Register reply (adapters + scheduled_jobs + checks). On startup
// the collector loads this and applies it immediately so polling resumes
// without waiting for the server. On reconnect the same path applies the live
// config; if a reconnect delivers an EMPTY or FAILED config the collector
// keeps its current jobs (see KEEP-CURRENT-ON-EMPTY below).
//
// KEEP-CURRENT-ON-EMPTY decision
// ------------------------------
// The Register/RPC wire protocol (CollectorConfig in proto/v1/collector.proto)
// has NO generation number and NO explicit "you now have zero jobs" flag —
// adapters/scheduled_jobs/checks are plain `repeated` fields. There is
// therefore no way to distinguish an INTENTIONAL "operator removed all jobs"
// from a TRANSIENT empty generation that Quarkus hands out mid-restart (before
// it has rehydrated the job set from its DB).
//
// Given that ambiguity, the safe default for a remote-proxy-style collector is
// KEEP-CURRENT-ON-EMPTY: an empty Register config is treated as "no opinion,
// keep what you have" and the running job set is NOT torn down. This trades a
// rare stale-config window (operator genuinely cleared all jobs, agent keeps
// polling until the next non-empty delta) for never silently stopping
// collection during a backend restart — which is the failure we are hardening
// against. The decision is logged loudly each time it fires.
//
// Recommended server-side follow-up (NOT implemented here per task scope):
// add an explicit generation counter or `intentional_empty` flag to
// CollectorConfig so the agent can honor a genuine "zero jobs" instruction,
// and/or have Quarkus rehydrate the full job set on registration so it never
// emits a transient empty generation.
package configcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/protobuf/proto"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Cache is a disk-backed store for the last-good CollectorConfig. Safe for
// concurrent use; writes are atomic (write-temp-then-rename).
type Cache struct {
	path string
	mu   sync.Mutex
}

// New returns a Cache backed by the file at path. The parent directory is
// created (0700) if missing so the cache write never fails on first boot.
func New(path string) (*Cache, error) {
	if path == "" {
		return nil, errors.New("configcache: empty path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("configcache: mkdir %s: %w", dir, err)
		}
	}
	return &Cache{path: path}, nil
}

// IsNonEmpty reports whether cfg carries any job-defining content (adapters,
// scheduled jobs, or checks). This is the single source of truth for the
// keep-current-on-empty decision: an empty config means "keep current".
func IsNonEmpty(cfg *collectorv1.CollectorConfig) bool {
	if cfg == nil {
		return false
	}
	return len(cfg.GetAdapters()) > 0 ||
		len(cfg.GetScheduledJobs()) > 0 ||
		len(cfg.GetChecks()) > 0
}

// Save atomically persists cfg to disk. Callers should only Save NON-EMPTY
// configs (IsNonEmpty true) — that is what makes the cache "last-known-GOOD".
// Saving is a no-op (returns nil) for an empty/nil config so a transient empty
// generation never clobbers a good cached config.
func (c *Cache) Save(cfg *collectorv1.CollectorConfig) error {
	if !IsNonEmpty(cfg) {
		return nil
	}
	data, err := proto.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("configcache marshal: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("configcache write tmp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("configcache rename: %w", err)
	}
	return nil
}

// Load reads the cached CollectorConfig. Returns (nil, nil) when no cache file
// exists yet (first boot) so callers can treat "no cache" the same as "empty".
func (c *Cache) Load() (*collectorv1.CollectorConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("configcache read: %w", err)
	}
	cfg := &collectorv1.CollectorConfig{}
	if err := proto.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("configcache unmarshal: %w", err)
	}
	return cfg, nil
}
