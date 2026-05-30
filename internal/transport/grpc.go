// Package transport handles the long-lived mTLS connection to the central
// IspWatch server: dial, register, and reconnect with exponential backoff.
//
// The Conn type is intentionally small. Stream handling for metrics/events
// will plug in once t1-5 lands (a separate file in this package).
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ispwatch/collector/internal/enrollment"
	"github.com/ispwatch/collector/internal/tools"
	"github.com/ispwatch/collector/internal/transport/wal"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	backoffBase = 1 * time.Second
	backoffMax  = 60 * time.Second
)

type Conn struct {
	cc        *grpc.ClientConn
	client    collectorv1.CollectorServiceClient
	session   *collectorv1.RegisterResponse
	tenantID  string
	collector string
	server    string
}

// Dial establishes the mTLS connection. Does NOT block on Register —
// the caller decides when to handshake (typically right after Dial).
func Dial(ctx context.Context, server, clientCert, clientKey, trustBundle, tenantID, collectorID string) (*Conn, error) {
	tlsCfg, err := buildTLSConfig(clientCert, clientKey, trustBundle, server)
	if err != nil {
		return nil, fmt.Errorf("build tls config: %w", err)
	}

	cc, err := grpc.NewClient(
		server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %w", err)
	}
	return &Conn{
		cc:        cc,
		client:    collectorv1.NewCollectorServiceClient(cc),
		tenantID:  tenantID,
		collector: collectorID,
		server:    server,
	}, nil
}

func (c *Conn) Close() error { return c.cc.Close() }

// Register sends the handshake and stores the response (config + token)
// for later reuse on reconnect. Capabilities are advertised so the server
// can validate ToolCommands before dispatching.
func (c *Conn) Register(ctx context.Context, version string, capabilities []string) (*collectorv1.RegisterResponse, error) {
	hostname, _ := os.Hostname()

	// D-14: auto-detect locally running services and advertise so the
	// server can suggest a HostTemplate. Best-effort with a tight 2s
	// budget — failure or timeout produces an empty list, never blocks
	// the handshake. Bounded by the agent (cap 16) and re-bounded by
	// Quarkus (cap 16) — defense in depth, T-04-08-02.
	detectCtx, detectCancel := context.WithTimeout(ctx, 2*time.Second)
	discovered := enrollment.DetectServices(detectCtx)
	detectCancel()

	req := &collectorv1.RegisterRequest{
		CollectorId:        c.collector,
		TenantId:           c.tenantID,
		Version:            version,
		Hostname:           hostname,
		Capabilities:       capabilities,
		DiscoveredServices: discovered,
	}
	resp, err := c.client.Register(ctx, req)
	if err != nil {
		return nil, err
	}
	c.session = resp
	return resp, nil
}

// RunOpts bundles all the knobs RunForever needs. Keeps the entrypoint
// signature manageable as more options accumulate (TLS, IDs, version, the
// metric ingress channel, the tools registry).
type RunOpts struct {
	Server      string
	ClientCert  string
	ClientKey   string
	TrustBundle string
	TenantID    string
	CollectorID string
	Version     string

	// WAL is the write-ahead log that backs the metric forwarder pipeline
	// (Plan 5, D-06 always-on). When set, StreamMetrics replays WAL entries
	// on startup and on every WALNotify signal instead of reading from a
	// channel. Either WAL+WALNotify or Metrics (legacy) must be set.
	WAL       *wal.WAL
	WALNotify <-chan struct{}

	// Metrics is the legacy in-channel path. Kept for backwards compatibility;
	// superseded by WAL+WALNotify in Plan 5. Set to nil when using WAL.
	//
	// Deprecated: use WAL + WALNotify instead.
	Metrics <-chan []*collectorv1.Metric

	// Events is the channel that drains check-emitted events (host.discovered
	// from snmp.autodiscover, icmp.scan, etc.) into the gRPC StreamEvents RPC.
	// Best-effort, no WAL — autodiscovery scans repeat on cadence so a lost
	// batch is recovered next run. nil = no event stream is opened.
	Events <-chan []*collectorv1.Event

	// SpanWAL is the write-ahead log that backs the trace forwarder pipeline
	// (Task 1, trace durability). When set, StreamSpans replays span WAL
	// entries on startup and on every SpanWALNotify signal — spans now
	// survive a backend restart or a multi-hour POP isolation, same as
	// metrics. nil = no span stream is opened (agent running without an
	// OTLP receiver).
	SpanWAL       *wal.SpanWAL
	SpanWALNotify <-chan struct{}

	// Tools holds the executors this Collector exposes. Their names become
	// the capabilities advertised in Register. nil means no ToolChannel is
	// opened (Collector is collection-only, no remote execution).
	Tools *tools.Registry

	// OnConfig fires after each successful Register with the FULL server-driven
	// CollectorConfig (adapters + scheduled_jobs + checks) before the per-list
	// callbacks below. Used by the config cache (Task 2) to persist the
	// last-known-good config to disk so the collector keeps its jobs across a
	// backend restart. nil = no config caching.
	OnConfig func(*collectorv1.CollectorConfig)

	// OnAdapters fires after each successful Register with the server-driven
	// adapter list. Receivers should diff against current state and start/stop
	// adapter goroutines accordingly. Empty slice = "no adapters configured";
	// caller may then fall back to CLI flags. May be nil during F.1 bring-up.
	OnAdapters func([]*collectorv1.AdapterConfig)

	// OnScheduledJobs fires after each successful Register with the server-
	// driven per-host job list (operator-defined Tool invocations: snmp.get,
	// ssh.ping, etc., on a cadence). Same swap-the-whole-set semantics as
	// OnAdapters. Empty slice = "operator has no jobs"; the scheduler then
	// stops everything (no bootstrap fallback — jobs are operator-only).
	OnScheduledJobs func([]*collectorv1.ScheduledJob)

	// OnTopologySender fires after each successful Register with a Sender
	// callback the LLDP discovery runner can use to push TopologyReport
	// messages to the central server. Replaced on every reconnect — the
	// runner reads the latest via atomic.Pointer to survive Conn churn.
	OnTopologySender func(send TopologySender)
}

// TopologySender is the callback signature exposed to the discovery layer.
// Wraps Conn.ReportTopology so the runner doesn't need a *Conn reference.
type TopologySender func(ctx context.Context, report *collectorv1.TopologyReport) (*collectorv1.TopologyAck, error)

// RunForever dials, registers, opens StreamMetrics (WAL-backed or legacy
// channel), and reconnects on any failure with exponential backoff + jitter.
// Honors ctx cancellation.
func RunForever(ctx context.Context, log *slog.Logger, opts RunOpts) {
	delay := backoffBase
	for {
		if err := ctx.Err(); err != nil {
			log.Info("shutdown requested, exiting connect loop")
			return
		}

		log.Info("dialing central server", "server", opts.Server)
		conn, err := Dial(ctx, opts.Server, opts.ClientCert, opts.ClientKey, opts.TrustBundle,
			opts.TenantID, opts.CollectorID)
		if err != nil {
			log.Error("dial failed", "err", err, "retry_in", delay)
			sleep(ctx, delay)
			delay = nextBackoff(delay)
			continue
		}

		caps := []string{}
		if opts.Tools != nil {
			caps = opts.Tools.Names()
		}

		regCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := conn.Register(regCtx, opts.Version, caps)
		cancel()
		if err != nil {
			log.Error("register failed", "err", err, "retry_in", delay)
			_ = conn.Close()
			sleep(ctx, delay)
			delay = nextBackoff(delay)
			continue
		}

		serverAdapters := resp.GetConfig().GetAdapters()
		adapterKinds := make([]string, 0, len(serverAdapters))
		for _, a := range serverAdapters {
			adapterKinds = append(adapterKinds, a.GetKind())
		}
		log.Info("registered",
			"session_token_prefix", safePrefix(resp.GetSessionToken(), 8),
			"batch_size", resp.GetConfig().GetMetricBatchSize(),
			"flush_seconds", resp.GetConfig().GetMetricFlushSeconds(),
			"heartbeat_seconds", resp.GetConfig().GetHeartbeatSeconds(),
			"capabilities", caps,
			"server_adapters", adapterKinds,
		)
		// Persist the full server config first (Task 2) so the cache reflects
		// this generation before any per-list callback applies it. The cache
		// itself no-ops on an empty config (keep-current-on-empty).
		if opts.OnConfig != nil {
			opts.OnConfig(resp.GetConfig())
		}
		// Server-driven adapter handoff. If the operator has wired adapters in
		// the UI, those win — instantiation happens on the receiver side
		// (opts.OnAdapters in t2-7.F.2). For F.1 we just signal the count so
		// the operator can verify the wire from logs.
		if opts.OnAdapters != nil {
			opts.OnAdapters(serverAdapters)
		}
		if opts.OnScheduledJobs != nil {
			opts.OnScheduledJobs(resp.GetConfig().GetScheduledJobs())
		}
		if opts.OnTopologySender != nil {
			// Bind the sender to THIS conn so the discovery runner targets the
			// active stream. On reconnect, OnTopologySender fires again with the
			// new conn — the runner stores the latest atomically.
			activeConn := conn
			opts.OnTopologySender(func(rctx context.Context, report *collectorv1.TopologyReport) (*collectorv1.TopologyAck, error) {
				return activeConn.ReportTopology(rctx, report)
			})
		}
		delay = backoffBase // reset on success

		// ToolChannel runs alongside StreamMetrics in its own goroutine when
		// a registry is provided. Both share the same gRPC connection.
		toolErrCh := make(chan error, 1)
		if opts.Tools != nil {
			go func() { toolErrCh <- conn.ToolChannel(ctx, log, opts.Tools) }()
		}

		// EventStream — drains check events (autodescoberta) into gRPC. Roda
		// em goroutine ao lado de StreamMetrics; erro nao quebra a metric stream
		// — o reconnect global reabre tudo no proximo ciclo.
		if opts.Events != nil {
			go func() {
				if err := conn.StreamEvents(ctx, log, opts.Events); err != nil {
					log.Warn("event stream ended, will reconnect", "err", err)
				}
			}()
		}

		// SpanStream — WAL-backed (Task 1, trace durability). Roda em goroutine
		// separada ao lado de StreamMetrics; erro não derruba a stream principal
		// (reconnect global cobre). On each reconnect the span WAL is replayed
		// so traces buffered during the outage are delivered.
		if opts.SpanWAL != nil {
			go func() {
				if err := conn.StreamSpans(ctx, log, opts.SpanWAL, opts.SpanWALNotify); err != nil {
					log.Warn("span stream ended, will reconnect", "err", err)
				}
			}()
		}

		// Metric stream: WAL-backed (Plan 5) takes precedence over legacy channel.
		if opts.WAL != nil {
			if err := conn.StreamMetrics(ctx, log, opts.WAL, opts.WALNotify); err != nil {
				log.Warn("metric stream ended, will reconnect", "err", err)
			}
		} else if opts.Metrics != nil {
			if err := conn.streamMetricsLegacy(ctx, log, opts.Metrics); err != nil {
				log.Warn("metric stream ended (legacy), will reconnect", "err", err)
			}
		} else if opts.Tools != nil {
			// Tool-only Collector: block on the tool stream.
			if err := <-toolErrCh; err != nil {
				log.Warn("tool channel ended, will reconnect", "err", err)
			}
		} else {
			<-ctx.Done()
		}
		_ = conn.Close()
		if ctx.Err() != nil {
			return
		}
	}
}

func buildTLSConfig(clientCert, clientKey, trustBundle, server string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	caBytes, err := os.ReadFile(trustBundle)
	if err != nil {
		return nil, fmt.Errorf("read trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("trust bundle %s contains no PEM certs", trustBundle)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   hostFromHostPort(server),
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func hostFromHostPort(hp string) string {
	for i := len(hp) - 1; i >= 0; i-- {
		if hp[i] == ':' {
			return hp[:i]
		}
	}
	return hp
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > backoffMax {
		d = backoffMax
	}
	// jitter: ±25%
	jitter := time.Duration(rand.Int63n(int64(d) / 2))
	return d - d/4 + jitter
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
