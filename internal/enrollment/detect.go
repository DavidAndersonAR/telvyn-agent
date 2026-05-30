// Package enrollment contains helpers the agent uses during the gRPC
// Register handshake — currently a single helper that auto-detects which
// services are running on the host so the server can suggest an appropriate
// HostTemplate (D-14 of Phase 4).
//
// The detection is intentionally best-effort: a failure to read /proc never
// blocks enrollment. Worst case the server sees an empty discovered_services
// list and the UI banner stays hidden.
package enrollment

import (
	"context"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

// known maps a process-name prefix to the canonical service name we report
// to the server. Multiple prefixes can point at the same service (e.g.
// "postmaster" is the master process on some Postgres installs); the
// detector dedups on the right-hand side.
//
// Why prefixes and not full names: /proc/[pid]/comm truncates to 15 chars
// on Linux. "redis-server" comes through as "redis-server" most kernels but
// can appear as "redis-ser" on older boxes — matching on a stable prefix
// covers both.
var known = map[string]string{
	"postgres":   "postgres",
	"postmaster": "postgres",
	"nginx":      "nginx",
	"redis-ser":  "redis",
	"dockerd":    "docker",
}

// maxServices caps the reported list. Defense in depth against a misbehaving
// host (cf. T-04-08-02 in the plan threat register) — the server also caps
// at 16 when reading.
const maxServices = 16

// listProcessNames is the test seam. In production it iterates the OS
// process table via gopsutil; tests overwrite it with a static slice so
// they don't need root or a real /proc.
var listProcessNames = defaultListProcessNames

func defaultListProcessNames(ctx context.Context) ([]string, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(procs))
	for _, p := range procs {
		// NameWithContext consults /proc/[pid]/comm and may fail for
		// zombies or processes that exited between Processes() and the
		// Name() call. Treat error as "skip this row" — never abort.
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// DetectServices scans the running process list and returns a sorted,
// deduplicated slice of canonical service names (subset of
// {postgres, nginx, redis, docker}). On any error it returns nil — callers
// must treat a nil result as "couldn't detect, do nothing fancy", not as
// an error.
//
// Result is capped at 16 elements (Phase 4 D-14, defense in depth).
func DetectServices(ctx context.Context) []string {
	names, err := listProcessNames(ctx)
	if err != nil {
		return nil
	}

	found := make(map[string]bool, 4)
	for _, name := range names {
		if name == "" {
			continue
		}
		for prefix, service := range known {
			if strings.HasPrefix(name, prefix) {
				found[service] = true
				break
			}
		}
	}

	if len(found) == 0 {
		return []string{}
	}

	out := make([]string, 0, len(found))
	for svc := range found {
		out = append(out, svc)
	}
	sort.Strings(out)

	if len(out) > maxServices {
		out = out[:maxServices]
	}
	return out
}
