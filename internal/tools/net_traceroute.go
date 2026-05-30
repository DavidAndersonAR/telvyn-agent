package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NetTraceroute runs the local `traceroute` binary against `target` from the
// collector itself. Unlike ssh.traceroute (which SSHes into a managed host and
// runs traceroute there), this is collector-direct and needs no credentials —
// useful for on-demand topology diagnostics from the NOC canvas.
//
// When `ttl` is set, the tool probes ONLY that single hop (uses `-f ttl -m ttl`),
// returning quickly and letting the caller incrementally build the path one hop
// at a time. Useful for streaming hops to a UI without holding open a 30s HTTP
// request that would otherwise time out.
//
// args schema:
//
//	target          string  required  IP or hostname
//	max_hops        number  optional  default 15, max 30 (full-path mode)
//	ttl             number  optional  when set, probe only this TTL (1..30)
//	timeout_seconds number  optional  per-probe wait, default 2
//
// Result map:
//
//	target       string  the IP/host that was probed
//	max_hops     int
//	hops         []object  parsed hop list (best-effort) — each {hop, host, rtt_ms}
//	exit_code    int
//	stdout       string  raw output (for the operator to see)
//	stderr       string
//	duration_ms  int
type NetTraceroute struct{}

func (NetTraceroute) Name() string { return "net.traceroute" }

func (NetTraceroute) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	target, err := requireString(args, "target")
	if err != nil {
		return nil, err
	}
	maxHops := optInt(args, "max_hops", 15)
	if maxHops <= 0 {
		maxHops = 15
	}
	if maxHops > 30 {
		maxHops = 30
	}
	waitSec := optInt(args, "timeout_seconds", 2)
	if waitSec <= 0 {
		waitSec = 2
	}
	singleTtl := optInt(args, "ttl", 0)

	// -n  no DNS lookups (faster, deterministic)
	// -w  per-probe wait
	// -m  max TTL / hop count
	// -f  first TTL (when single-hop mode, equal to -m so we only probe N)
	var cmd *exec.Cmd
	if singleTtl > 0 {
		if singleTtl > 30 {
			singleTtl = 30
		}
		ttlStr := strconv.Itoa(singleTtl)
		cmd = exec.CommandContext(ctx, "traceroute",
			"-n", "-w", strconv.Itoa(waitSec), "-f", ttlStr, "-m", ttlStr, target)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute",
			"-n", "-w", strconv.Itoa(waitSec), "-m", strconv.Itoa(maxHops), target)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	exitCode := 0
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return nil, fmt.Errorf("net.traceroute: spawn failed: %w", runErr)
	}

	out := stdout.String()
	hops := parseLocalTraceroute(out)
	completed := false
	if len(hops) > 0 {
		if lastRow, ok := hops[len(hops)-1].(map[string]any); ok {
			if last, ok := lastRow["host"].(string); ok && last == target {
				completed = true
			}
		}
	}

	return map[string]any{
		"target":      target,
		"max_hops":    float64(maxHops),
		"hops":        hops,
		"hops_seen":   float64(len(hops)),
		"completed":   completed,
		"exit_code":   float64(exitCode),
		"stdout":      out,
		"stderr":      stderr.String(),
		"duration_ms": float64(dur.Milliseconds()),
	}, nil
}

// parseLocalTraceroute extracts {hop, host, rtt_ms} from `traceroute -n`
// stdout. Best-effort — malformed lines are skipped silently.
//
// Expected line shape (`-n` strips reverse-DNS):
//
//	" 1  172.24.0.1  0.003 ms  0.003 ms  0.001 ms"
//	" 5  *  *  *"
//
// We pick the FIRST non-* IP and the FIRST RTT to keep the row compact.
//
// Return type is []any (not []map[string]any) so the Struct marshaler at the
// tool-channel boundary can serialize each row — proto's structpb supports
// []any → ListValue but rejects strictly-typed slices.
func parseLocalTraceroute(stdout string) []any {
	var hops []any
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hopNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		row := map[string]any{"hop": float64(hopNum)}
		// Walk remaining fields. Pick first non-"*" as host; subsequent
		// numeric token (followed by "ms") becomes rtt_ms.
		var host string
		var rtt float64
		for i := 1; i < len(fields); i++ {
			tok := fields[i]
			if host == "" && tok != "*" && !isNumeric(tok) {
				host = tok
				continue
			}
			if rtt == 0 && isNumeric(tok) {
				if v, err := strconv.ParseFloat(tok, 64); err == nil {
					rtt = v
				}
			}
		}
		if host != "" {
			row["host"] = host
		}
		if rtt > 0 {
			row["rtt_ms"] = rtt
		}
		hops = append(hops, row)
	}
	return hops
}

// isNumeric returns true only for strings that parse as a single float —
// IPv4 addresses like "172.24.0.1" must NOT count as numeric or the parser
// confuses them with the RTT field. ParseFloat handles both cases cleanly
// (single dot allowed for decimals, multiple dots rejected).
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
