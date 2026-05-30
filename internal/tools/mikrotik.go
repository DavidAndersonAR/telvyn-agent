package tools

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-routeros/routeros/v3"
)

// MikrotikExec runs a RouterOS API command and returns the structured reply.
// Faster and richer than SSH'ing in (`ssh.exec` to a Mikrotik), and avoids
// the brittleness of parsing CLI banners.
//
// args schema:
//
//	host       string  required  device IP/hostname
//	port       number  optional  default 8728 (plain) or 8729 (TLS)
//	username   string  required  RouterOS user with API permission
//	password   string  required  matching password
//	use_tls    bool    optional  default false
//	timeout_seconds  number   optional  default 10
//	command    []string  required  RouterOS sentence words, e.g.
//	                              ["/system/resource/print"] or
//	                              ["/interface/print", "?disabled=false"]
//
// Result:
//
//	raw      []map<string,string>  one entry per !re sentence in the reply
//	metrics  []map<...>            present only when `command` matches a
//	                              recognized "rich" command (today: just
//	                              /system/resource/print). Add more parsers
//	                              as we cover more device queries.
//
// Why no map-based generic metric extraction: RouterOS returns ALL fields as
// strings ("cpu-load=42", "free-memory=33554432"). Without per-command
// knowledge of which fields are gauges and what units, generic conversion
// produces garbage.
type MikrotikExec struct{}

func (MikrotikExec) Name() string { return "mikrotik.exec" }

func (MikrotikExec) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	host, err := requireString(args, "host")
	if err != nil {
		return nil, err
	}
	username, err := requireString(args, "username")
	if err != nil {
		return nil, err
	}
	password, err := requireString(args, "password")
	if err != nil {
		return nil, err
	}
	cmdWords, err := requireStringSlice(args, "command")
	if err != nil {
		return nil, err
	}

	useTLS := optBool(args, "use_tls", false)
	port := optInt(args, "port", 0)
	if port == 0 {
		if useTLS {
			port = 8729
		} else {
			port = 8728
		}
	}
	timeoutSec := optInt(args, "timeout_seconds", 10)
	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := dialMikrotik(ctx, addr, username, password, useTLS, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	start := time.Now()
	reply, err := client.RunArgs(cmdWords)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("mikrotik.exec %v: %w", cmdWords, err)
	}

	raw := make([]any, 0, len(reply.Re))
	for _, sent := range reply.Re {
		row := make(map[string]any, len(sent.Map))
		for k, v := range sent.Map {
			row[k] = v
		}
		raw = append(raw, row)
	}

	metrics := []any{}
	// Recognize the well-known query and turn it into typed metrics. Using
	// the first word as the dispatch key keeps the matching cheap and
	// extension obvious (add another case when we cover more queries).
	if len(cmdWords) >= 1 {
		switch strings.TrimRight(cmdWords[0], "/") {
		case "/system/resource/print":
			metrics = parseMikrotikSystemResource(reply, host)
		}
	}

	return map[string]any{
		"raw":         raw,
		"command":     cmdWords,
		"duration_ms": float64(durationMs),
		"metrics":     metrics,
	}, nil
}

// dialMikrotik opens an API connection (TLS optional) with auth completed.
// Honors ctx by closing the connection from a watchdog goroutine.
func dialMikrotik(ctx context.Context, addr, user, pass string, useTLS bool, timeout time.Duration) (*routeros.Client, error) {
	type result struct {
		c   *routeros.Client
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var c *routeros.Client
		var err error
		if useTLS {
			// In production the operator should pin the device's cert; for the
			// internal tool we accept the device's self-signed cert (Mikrotik
			// default) — defensible because the OPS network here is trusted
			// already (we're inside the customer's site Collector).
			c, err = routeros.DialTLSTimeout(addr, user, pass, &tls.Config{InsecureSkipVerify: true}, timeout)
		} else {
			c, err = routeros.DialTimeout(addr, user, pass, timeout)
		}
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("routeros dial %s: %w", addr, r.err)
		}
		return r.c, nil
	}
}

// parseMikrotikSystemResource turns /system/resource/print into 4 numeric
// metrics. RouterOS field names → metric names:
//
//	cpu-load            → mikrotik.cpu_load_pct
//	free-memory         → mikrotik.free_memory_bytes
//	total-memory        → mikrotik.total_memory_bytes
//	uptime              → mikrotik.uptime_seconds (parsed from "1w2d3h4m5s")
func parseMikrotikSystemResource(reply *routeros.Reply, host string) []any {
	if len(reply.Re) == 0 {
		return nil
	}
	m := reply.Re[0].Map
	out := []any{}
	tags := map[string]any{"device": host}

	if v, ok := m["cpu-load"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			out = append(out, map[string]any{
				"name": "mikrotik.cpu_load_pct", "value": f,
				"source": "mikrotik", "tags": tags,
			})
		}
	}
	if v, ok := m["free-memory"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			out = append(out, map[string]any{
				"name": "mikrotik.free_memory_bytes", "value": f,
				"source": "mikrotik", "tags": tags,
			})
		}
	}
	if v, ok := m["total-memory"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			out = append(out, map[string]any{
				"name": "mikrotik.total_memory_bytes", "value": f,
				"source": "mikrotik", "tags": tags,
			})
		}
	}
	if v, ok := m["uptime"]; ok {
		out = append(out, map[string]any{
			"name": "mikrotik.uptime_seconds", "value": parseRouterOSUptime(v),
			"source": "mikrotik", "tags": tags,
		})
	}
	return out
}

// parseRouterOSUptime turns "1w2d3h4m5s" into seconds. Returns 0 on parse
// failure — caller treats 0 as "no data" (a freshly booted box might be
// genuinely 0 seconds, which is acceptable noise for this metric).
func parseRouterOSUptime(s string) float64 {
	multipliers := map[byte]float64{
		's': 1,
		'm': 60,
		'h': 3600,
		'd': 86400,
		'w': 604800,
	}
	var total float64
	var num strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			num.WriteByte(c)
			continue
		}
		mult, ok := multipliers[c]
		if !ok {
			continue
		}
		if num.Len() == 0 {
			continue
		}
		n, _ := strconv.ParseFloat(num.String(), 64)
		total += n * mult
		num.Reset()
	}
	return total
}

func optBool(args map[string]any, key string, def bool) bool {
	v, ok := args[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
