package tools

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ssh.ping / ssh.traceroute / ssh.mtr: log into a managed host via SSH and
// run the local diagnostic command targeting `target`. Variants of ssh.exec
// with output parsers, so the operator gets a stable metric series instead
// of free-form stdout.
//
// Common args (same as ssh.exec auth surface):
//
//	host, port?, user, private_key|password, known_host?, timeout?
//
// Plus per-tool:
//
//	target  string  required  what to ping/traceroute/mtr at — typically
//	                         a public anchor (8.8.8.8, customer gateway).
//	count   number  optional  echoes / cycles, default 4
//
// Ping output assumed Linux/BSD `ping -c N` shape:
//
//	"X packets transmitted, Y received, Z% packet loss"
//	"rtt min/avg/max/mdev = a/b/c/d ms"
//
// Mikrotik / Cisco devices speak different ping CLIs — for those use
// mikrotik.exec / a future cisco.exec rather than ssh.ping.

// ---------- ssh.ping ----------

type SSHPing struct{}

func (SSHPing) Name() string { return "ssh.ping" }

func (SSHPing) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	target, err := requireString(args, "target")
	if err != nil {
		return nil, err
	}
	count := optInt(args, "count", 4)
	if count <= 0 {
		count = 4
	}
	if count > 20 {
		count = 20
	}
	cmd := fmt.Sprintf("ping -c %d -W 2 %s", count, shellQuote(target))
	stdout, stderr, exit, dur, err := runRemoteCommand(ctx, args, cmd)
	if err != nil {
		return nil, err
	}
	rttAvg, lossPct := parsePingOutput(stdout)
	return map[string]any{
		"stdout":      stdout,
		"stderr":      stderr,
		"exit_code":   float64(exit),
		"duration_ms": float64(dur.Milliseconds()),
		"target":      target,
		"metrics": []any{
			map[string]any{"name": "ssh.ping.rtt_ms", "value": rttAvg, "source": "ssh.ping",
				"tags": map[string]any{"target": target}},
			map[string]any{"name": "ssh.ping.loss_pct", "value": lossPct, "source": "ssh.ping",
				"tags": map[string]any{"target": target}},
		},
	}, nil
}

// ---------- ssh.traceroute ----------

type SSHTraceroute struct{}

func (SSHTraceroute) Name() string { return "ssh.traceroute" }

func (SSHTraceroute) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	target, err := requireString(args, "target")
	if err != nil {
		return nil, err
	}
	maxHops := optInt(args, "max_hops", 30)
	if maxHops <= 0 {
		maxHops = 30
	}
	if maxHops > 64 {
		maxHops = 64
	}
	cmd := fmt.Sprintf("traceroute -n -w 2 -m %d %s", maxHops, shellQuote(target))
	stdout, stderr, exit, dur, err := runRemoteCommand(ctx, args, cmd)
	if err != nil {
		return nil, err
	}
	hopsSeen, completed := parseTracerouteOutput(stdout, target)
	completedNum := 0.0
	if completed {
		completedNum = 1.0
	}
	return map[string]any{
		"stdout":      stdout,
		"stderr":      stderr,
		"exit_code":   float64(exit),
		"duration_ms": float64(dur.Milliseconds()),
		"target":      target,
		"metrics": []any{
			map[string]any{"name": "ssh.traceroute.hops", "value": float64(hopsSeen),
				"source": "ssh.traceroute",
				"tags":   map[string]any{"target": target}},
			map[string]any{"name": "ssh.traceroute.completed", "value": completedNum,
				"source": "ssh.traceroute",
				"tags":   map[string]any{"target": target}},
		},
	}, nil
}

// ---------- ssh.mtr ----------

type SSHMtr struct{}

func (SSHMtr) Name() string { return "ssh.mtr" }

func (SSHMtr) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	target, err := requireString(args, "target")
	if err != nil {
		return nil, err
	}
	cycles := optInt(args, "count", 5)
	if cycles <= 0 {
		cycles = 5
	}
	if cycles > 30 {
		cycles = 30
	}
	cmd := fmt.Sprintf("mtr -n --report --report-cycles %d %s", cycles, shellQuote(target))
	stdout, stderr, exit, dur, err := runRemoteCommand(ctx, args, cmd)
	if err != nil {
		return nil, err
	}
	lastLossPct, lastAvgMs := parseMtrLastHop(stdout)
	return map[string]any{
		"stdout":      stdout,
		"stderr":      stderr,
		"exit_code":   float64(exit),
		"duration_ms": float64(dur.Milliseconds()),
		"target":      target,
		"metrics": []any{
			map[string]any{"name": "ssh.mtr.last_hop_loss_pct", "value": lastLossPct,
				"source": "ssh.mtr",
				"tags":   map[string]any{"target": target}},
			map[string]any{"name": "ssh.mtr.last_hop_avg_ms", "value": lastAvgMs,
				"source": "ssh.mtr",
				"tags":   map[string]any{"target": target}},
		},
	}, nil
}

// ---------- shared connect/exec ----------

// runRemoteCommand opens a fresh SSH session, runs `cmd`, and returns the
// captured streams + exit code. Mirrors SSHExec.Execute's connection plumbing
// (auth, host-key verification, output cap, ctx kill) — kept inline rather
// than refactored to avoid churning ssh.go's API while we iterate.
func runRemoteCommand(ctx context.Context, args map[string]any, cmd string) (stdout, stderr string, exitCode int, duration time.Duration, err error) {
	host, err := requireString(args, "host")
	if err != nil {
		return "", "", 0, 0, err
	}
	user, err := requireString(args, "user")
	if err != nil {
		return "", "", 0, 0, err
	}
	port := optInt(args, "port", sshDefaultPort)
	timeoutSec := optInt(args, "timeout", 30)

	authMethods, err := buildAuthMethods(args)
	if err != nil {
		return "", "", 0, 0, err
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if khLine, ok := args["known_host"].(string); ok && khLine != "" {
		_, _, pubKey, _, _, perr := ssh.ParseKnownHosts([]byte(khLine))
		if perr != nil {
			return "", "", 0, 0, fmt.Errorf("parse known_host: %w", perr)
		}
		hostKeyCallback = ssh.FixedHostKey(pubKey)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshDialTimeout,
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	dialErrCh := make(chan error, 1)
	var client *ssh.Client
	go func() {
		var derr error
		client, derr = ssh.Dial("tcp", addr, cfg)
		dialErrCh <- derr
	}()
	select {
	case <-ctx.Done():
		return "", "", 0, 0, ctx.Err()
	case derr := <-dialErrCh:
		if derr != nil {
			return "", "", 0, 0, fmt.Errorf("ssh dial %s: %w", addr, derr)
		}
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	var so, se cappedBuffer
	so.cap = sshOutputCapBytes
	se.cap = sshOutputCapBytes
	session.Stdout = &so
	session.Stderr = &se

	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- session.Run(cmd) }()

	var runErr error
	select {
	case <-runCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		runErr = runCtx.Err()
	case runErr = <-runErrCh:
	}
	duration = time.Since(start)
	exitCode = 0
	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			exitCode = -1
		}
	}
	return so.String(), se.String(), exitCode, duration, nil
}

// shellQuote wraps a string in single quotes and escapes embedded ones.
// Targets are passed by the operator/IA — this is defense in depth so that
// a host name like `1.1.1.1; rm -rf /` parses as a single arg.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ---------- output parsers ----------

var (
	pingLossRE = regexp.MustCompile(`(?m)(\d+(?:\.\d+)?)% packet loss`)
	pingRTTRE  = regexp.MustCompile(`(?m)min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/[\d.]+(?:/[\d.]+)?\s*ms`)
)

func parsePingOutput(out string) (rttAvgMs, lossPct float64) {
	if m := pingLossRE.FindStringSubmatch(out); len(m) == 2 {
		lossPct, _ = strconv.ParseFloat(m[1], 64)
	} else {
		lossPct = 100.0
	}
	if m := pingRTTRE.FindStringSubmatch(out); len(m) == 2 {
		rttAvgMs, _ = strconv.ParseFloat(m[1], 64)
	}
	return
}

// parseTracerouteOutput counts numbered hop lines and decides whether the
// final hop is the requested target (resolved at any rate — since we run
// `-n` the line shows IPs, not hostnames).
func parseTracerouteOutput(out, target string) (hops int, completed bool) {
	hopLine := regexp.MustCompile(`^\s*(\d+)\s+(\S+)`)
	var lastIP string
	for _, ln := range strings.Split(out, "\n") {
		if m := hopLine.FindStringSubmatch(ln); len(m) == 3 {
			n, _ := strconv.Atoi(m[1])
			if n > hops {
				hops = n
			}
			if m[2] != "*" {
				lastIP = m[2]
			}
		}
	}
	completed = lastIP != "" && (lastIP == target || strings.HasPrefix(lastIP, target))
	return
}

// parseMtrLastHop reads the last numeric-prefix line of `mtr --report` and
// extracts loss% (col 3 in v0.93+) and avg ms. Format example:
//
//	HOST: foo                        Loss%   Snt   Last   Avg  Best  Wrst StDev
//	  1.|-- 192.168.1.1              0.0%    5    0.5   0.6   0.5   0.7   0.1
//	  2.|-- 8.8.8.8                  0.0%    5    9.1   9.5   9.0  10.2   0.5
//
// We pick the last numbered hop. If parsing fails (truncated, format change),
// returns 100% loss + 0ms — which surfaces "broken probe" without crashing.
func parseMtrLastHop(out string) (lossPct, avgMs float64) {
	hopLine := regexp.MustCompile(`^\s*\d+\.\|--\s+\S+\s+([\d.]+)%\s+\d+\s+[\d.]+\s+([\d.]+)`)
	lossPct = 100.0
	for _, ln := range strings.Split(out, "\n") {
		if m := hopLine.FindStringSubmatch(ln); len(m) == 3 {
			lp, _ := strconv.ParseFloat(m[1], 64)
			ag, _ := strconv.ParseFloat(m[2], 64)
			lossPct, avgMs = lp, ag
		}
	}
	return
}
