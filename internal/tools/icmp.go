package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IcmpPing sends ICMP echo requests to a single target and emits two metrics:
// avg RTT in ms and loss percentage. Used as a scheduled job per managed host
// so the operator gets a per-equipment latency series.
//
// args schema:
//
//	target          string  required  hostname or IP (resolved at exec time)
//	count           number  optional  echo packets to send, default 4, max 20
//	interval_ms     number  optional  spacing between echoes, default 200ms
//	timeout_seconds number  optional  per-echo wait, default 2s
//	source          string  optional  Metric.source override, default "icmp"
//	host_id         string  optional  Metric.host_id override; defaults to
//	                                  the resolved target string. The job's
//	                                  host_id wins anyway when scheduled —
//	                                  this is for one-off ToolChannel calls.
//
// Result:
//
//	metrics:[
//	  {name:"icmp.rtt_ms",   value: <avg RTT, ms>,         source:"icmp"},
//	  {name:"icmp.loss_pct", value: <loss percent 0..100>, source:"icmp"},
//	]
//
// Privileges: uses Linux's "DGRAM ICMP" mode (`udp4`/`udp6` socket flavor),
// which does not require CAP_NET_RAW as long as the kernel's
// `net.ipv4.ping_group_range` includes the agent's GID. The container does
// this by default for GID 0 (root); for non-root deployments the runner
// either widens the range or grants CAP_NET_RAW.
type IcmpPing struct{}

func (IcmpPing) Name() string { return "icmp.ping" }

func (IcmpPing) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
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
	intervalMs := optInt(args, "interval_ms", 200)
	if intervalMs < 0 {
		intervalMs = 200
	}
	timeoutSec := optInt(args, "timeout_seconds", 2)
	if timeoutSec <= 0 {
		timeoutSec = 2
	}
	source := optString(args, "source", "icmp")
	hostIDOverride := optString(args, "host_id", "")

	// Resolve once — keeps every echo aimed at the same address even if DNS
	// flips mid-run, which would otherwise pollute the loss% number.
	resolved, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return nil, fmt.Errorf("icmp.ping: resolve %q: %w", target, err)
	}

	listenNet := "udp4"
	dest := &net.UDPAddr{IP: resolved.IP}
	echoType := icmp.Type(ipv4.ICMPTypeEcho)
	proto := 1 // ICMPv4
	if resolved.IP.To4() == nil {
		listenNet = "udp6"
		echoType = icmp.Type(ipv6.ICMPTypeEchoRequest)
		proto = 58 // ICMPv6
	}
	// "0.0.0.0" lets the kernel pick the source IP via the route. ":0"
	// gives us a random ephemeral source port (icmp identifier on Linux).
	listenAddr := "0.0.0.0"
	if listenNet == "udp6" {
		listenAddr = "::"
	}

	conn, err := icmp.ListenPacket(listenNet, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("icmp.ping: listen %s: %w", listenNet, err)
	}
	defer conn.Close()

	id := os.Getpid() & 0xFFFF
	var sumRTT time.Duration
	received := 0
	interval := time.Duration(intervalMs) * time.Millisecond
	perEcho := time.Duration(timeoutSec) * time.Second

	for seq := 0; seq < count; seq++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		msg := icmp.Message{
			Type: echoType, Code: 0,
			Body: &icmp.Echo{
				ID: id, Seq: seq,
				// Payload identifies the echo for our parser without needing
				// to track sequence numbers across goroutines.
				Data: []byte("ispwatch.icmp.ping"),
			},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			return nil, fmt.Errorf("icmp.ping: marshal: %w", err)
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, dest); err != nil {
			// Per-echo failures are logged via the loss count, not the error
			// return — one bad packet shouldn't abort the rest of the run.
			continue
		}
		// Read until we either get OUR reply (matched id+seq) or hit
		// the per-echo deadline. Other replies on the socket (rare with
		// DGRAM mode but possible) are dropped and we keep waiting.
		_ = conn.SetReadDeadline(time.Now().Add(perEcho))
		matched, rtt, err := waitForReply(conn, proto, id, seq, start)
		if err == nil && matched {
			sumRTT += rtt
			received++
		}
		// Inter-echo spacing — skip after the last one so we don't sleep
		// for nothing when the caller timeout is tight.
		if seq < count-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
			}
		}
	}

	lossPct := 0.0
	avgRTTms := 0.0
	if count > 0 {
		lossPct = float64(count-received) / float64(count) * 100.0
	}
	if received > 0 {
		avgRTTms = float64(sumRTT.Microseconds()) / float64(received) / 1000.0
	}

	hostID := hostIDOverride
	if hostID == "" {
		hostID = target
	}

	makeMetric := func(name string, val float64) map[string]any {
		m := map[string]any{
			"name":   name,
			"value":  val,
			"source": source,
		}
		if hostIDOverride != "" {
			m["host_id"] = hostIDOverride
		}
		return m
	}

	return map[string]any{
		"target":   target,
		"resolved": resolved.IP.String(),
		"sent":     float64(count),
		"received": float64(received),
		"metrics": []any{
			makeMetric("icmp.rtt_ms", avgRTTms),
			makeMetric("icmp.loss_pct", lossPct),
		},
	}, nil
}

// waitForReply blocks until we read a reply matching seq or the deadline
// elapses. Returns matched=false on timeout (no error).
//
// Note on the ID field: in Linux DGRAM ICMP mode (`udp4` socket flavor) the
// kernel rewrites the Echo identifier to the locally-assigned UDP port number
// on outbound and only delivers replies whose echo.ID matches that same port
// number. Userspace can therefore NOT match on echo.ID — the value you set
// during Marshal is ignored on the wire. Matching by seq alone is sufficient
// because (a) our loop emits each seq exactly once and (b) the kernel-level
// filter already ensures we only receive replies that belong to our socket.
func waitForReply(conn *icmp.PacketConn, proto, _ /*id*/, seq int, start time.Time) (matched bool, rtt time.Duration, err error) {
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return false, 0, nil
			}
			return false, 0, err
		}
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.Seq == seq {
			return true, time.Since(start), nil
		}
		// Reply for a different sequence — ignore and keep reading until
		// the deadline (ours might still be in flight).
	}
}
