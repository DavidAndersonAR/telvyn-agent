// Command collector is the IspWatch on-prem agent. It connects via mTLS
// to the central server, registers itself, runs configured adapters, and
// streams the resulting metrics back.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ispwatch/collector/internal/adapters"
	"github.com/ispwatch/collector/internal/apm/concentrator"
	"github.com/ispwatch/collector/internal/apm/obfuscate"
	"github.com/ispwatch/collector/internal/apm/sampler"
	"github.com/ispwatch/collector/internal/apm/statsfwd"
	"github.com/ispwatch/collector/internal/checks"
	"github.com/ispwatch/collector/internal/clusteragent"
	"github.com/ispwatch/collector/internal/config"
	"github.com/ispwatch/collector/internal/configcache"
	"github.com/ispwatch/collector/internal/configpull"
	"github.com/ispwatch/collector/internal/discovery/lldp"
	"github.com/ispwatch/collector/internal/ebpf"
	"github.com/ispwatch/collector/internal/ebpf/common"
	"github.com/ispwatch/collector/internal/langdetect"
	"github.com/ispwatch/collector/internal/logs"
	"github.com/ispwatch/collector/internal/otlp"
	"github.com/ispwatch/collector/internal/quarkus"
	"github.com/ispwatch/collector/internal/sbom"
	"github.com/ispwatch/collector/internal/webhook"

	"github.com/ispwatch/collector/internal/scheduler"
	"github.com/ispwatch/collector/internal/selfmetrics"
	"github.com/ispwatch/collector/internal/tools"
	"github.com/ispwatch/collector/internal/transport"
	"github.com/ispwatch/collector/internal/transport/wal"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/vishvananda/netns"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// deriveHttpEndpoint converte o gRPC endpoint do servidor (host:8443) em URL
// HTTPS (host:8444) — Phase 5b passou o pull endpoint pra mTLS, então
// o cliente fala HTTPS na porta dedicada (não 8080, que é plain HTTP pra UI).
// A porta HTTPS é gRPC+1 (convenção do compose dev: 8443/8444, 18443/18444…),
// permitindo override via grpcEndpoint customizado (ex: dogfood Multipass que
// usa portas altas porque 8443/8444 são reservadas pelo HTTP.sys do Windows).
// Env override ISPWATCH_HTTP_ENDPOINT tem prioridade absoluta.
func deriveHttpEndpoint(grpcEndpoint string) string {
	if override := os.Getenv("ISPWATCH_HTTP_ENDPOINT"); override != "" {
		return override
	}
	host := grpcEndpoint
	port := 8443
	if i := lastIndex(host, ":"); i >= 0 {
		if p, err := strconv.Atoi(host[i+1:]); err == nil {
			port = p
		}
		host = host[:i]
	}
	return fmt.Sprintf("https://%s:%d", host, port+1)
}

func lastIndex(s, sep string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep[0] {
			return i
		}
	}
	return -1
}

// Version is set at build time via -ldflags. Defaults to "dev" for local runs.
var Version = "dev"

func main() {
	// Intercept --version / -version / -v early — before config.Parse, which
	// requires mTLS flags. This keeps `ispwatch-agent --version` working in
	// tarball smoke tests and ops sanity checks (Plan 03-09 release pipeline).
	enrollOnly := false
	webhookOnly := false
	for _, a := range os.Args[1:] {
		switch a {
		case "--version", "-version", "-v":
			fmt.Printf("ispwatch-agent %s\n", Version)
			os.Exit(0)
		case "--enroll-only", "-enroll-only":
			enrollOnly = true
		case "--webhook", "-webhook":
			webhookOnly = true
		}
	}

	// Bootstrap enrollment: ran by entrypoint.sh on first boot when
	// ISPWATCH_BOOTSTRAP_TOKEN is set. Mints a unique cert per agent instance
	// (1 agent = 1 host model) and writes it to the PKI dir. After this exits
	// successfully, entrypoint sources identity.env and re-execs the agent
	// normally. Standalone binary => testable as `collector --enroll-only`.
	if enrollOnly {
		enrollLog := newLogger("info")
		ctx := context.Background()
		if err := enrollIfNeeded(ctx, enrollLog); err != nil {
			enrollLog.Error("enrollment failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if webhookOnly {
		// Modo Mutating Webhook server. Lê config de env vars — não
		// reutiliza config.Parse pois esse binário roda como Deployment
		// separado (não DaemonSet), com identidade mTLS própria.
		whLog := newLogger("info")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() { <-sigCh; cancel() }()

		cfg := webhook.Config{
			ListenAddr:      getenvOr("ISPWATCH_WEBHOOK_ADDR", webhook.DefaultListenAddr),
			CertDir:         getenvOr("ISPWATCH_WEBHOOK_CERT_DIR", webhook.DefaultCertDir),
			IngestURL:       mustEnv("ISPWATCH_INGEST_URL"),
			Token:           mustEnv("ISPWATCH_INGEST_TOKEN"),
			AgentImage:      getenvOr("ISPWATCH_AGENT_IMAGE", "localhost/telvyn-agent:local"),
			OtlpEndpointEnv: getenvOr("ISPWATCH_OTLP_ENDPOINT", "http://$(NODE_IP):4318"),
			OtlpProtocol:    getenvOr("ISPWATCH_OTLP_PROTOCOL", "http/protobuf"),
			Log:             whLog,
		}
		srv := webhook.New(cfg)
		if err := srv.Run(ctx); err != nil {
			whLog.Error("webhook server exited", "err", err)
			os.Exit(1)
		}
		return
	}

	// Modo ingest certless (Datadog-style): manda telemetria OTLP pro gateway
	// /api/ingest/v1 com Bearer token, sem enrollment/mTLS/cert por agent.
	// Ativado por ISPWATCH_INGEST_URL (+ ISPWATCH_INGEST_TOKEN).
	if ingestURL := strings.TrimSpace(os.Getenv("ISPWATCH_INGEST_URL")); ingestURL != "" {
		runIngestMode(ingestURL)
		return
	}

	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	log := newLogger(cfg.LogLevel)
	log.Info("ispwatch collector starting",
		"version", Version,
		"tenant", cfg.TenantID,
		"collector", cfg.CollectorID,
		"server", cfg.Server,
		"known_adapter_kinds", adapters.KnownKinds(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("signal received, shutting down", "signal", s.String())
		cancel()
	}()

	// WAL bootstrap (Plan 5, D-06 always-on). Opened before checks.Runtime and
	// scheduler.Runtime so any metric produced before the first gRPC connection
	// is safely persisted to disk rather than lost.
	// Directory created with 0700 so only the agent user can access WAL data
	// (T-02-05-01 mitigation).
	if dir := filepath.Dir(cfg.WalPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Error("wal: failed to create directory", "path", dir, "err", err)
			os.Exit(1)
		}
	}
	walDB, err := wal.Open(cfg.WalPath, cfg.WalMaxBytes)
	if err != nil {
		log.Error("wal: open failed", "path", cfg.WalPath, "err", err)
		os.Exit(1)
	}
	defer walDB.Close()
	log.Info("wal: opened", "path", cfg.WalPath, "max_mb", cfg.WalMaxBytes/1024/1024)

	// Span WAL (Task 1, trace durability). Separate bbolt file + independent
	// byte cap so a span flood never eats the metrics WAL budget. Opened with
	// the same 0700 dir handling as the metrics WAL.
	if dir := filepath.Dir(cfg.SpanWalPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Error("span wal: failed to create directory", "path", dir, "err", err)
			os.Exit(1)
		}
	}
	spanWAL, err := wal.OpenSpanWAL(cfg.SpanWalPath, cfg.SpanWalMaxBytes)
	if err != nil {
		log.Error("span wal: open failed", "path", cfg.SpanWalPath, "err", err)
		os.Exit(1)
	}
	defer spanWAL.Close()
	log.Info("span wal: opened", "path", cfg.SpanWalPath, "max_mb", cfg.SpanWalMaxBytes/1024/1024)

	// Producer aggregates metrics from all upstream channels (checks, scheduler,
	// adapters) and persists each MetricBatch to the WAL before signalling the
	// sender. batchSize=500 and flushInterval=1s match the Quarkus VmRemoteWriter
	// throughput assumptions from Plan 2.
	producer := transport.NewProducer(walDB, cfg.CollectorID, log, 500, 1*time.Second)
	go producer.RunFlushLoop(ctx)

	// out is the shared channel all upstream producers push []*Metric slices into.
	// Adapters push directly; checks.Runtime and scheduler.Runtime also push here.
	// The Producer.FanIn call below merges this channel (and any future additional
	// sources) into the WAL pipeline.
	out := make(chan []*collectorv1.Metric, 256)

	// FanIn wires the shared out channel into the Producer. When additional
	// per-source channels are added (e.g. per-adapter dedicated channels) they
	// can be passed as extra args here without changing downstream code.
	producer.FanIn(ctx, out)

	runtime := newAdapterRuntime(ctx, log, out, cfg)

	// Tools the central server can dispatch to this Collector. Names become
	// the capabilities advertised in Register; Quarkus rejects ToolCommands
	// for tools not on this list (defense in depth). The same registry feeds
	// the in-agent scheduler — operator-defined ScheduledJobs invoke these
	// executors at their configured cadence.
	registry := tools.NewRegistry()
	registry.Register(tools.SSHExec{})
	registry.Register(tools.SnmpGet{})
	registry.Register(tools.SnmpWalk{})
	registry.Register(tools.IcmpPing{})
	registry.Register(tools.NetTraceroute{})
	registry.Register(tools.SSHPing{})
	registry.Register(tools.SSHTraceroute{})
	registry.Register(tools.SSHMtr{})
	registry.Register(tools.MikrotikExec{})
	registry.Register(tools.MikrotikDiscoverTopology{})
	registry.Register(tools.LldpDiscover{})
	registry.Register(tools.K8sLogs{})

	// Scheduler runs operator-scheduled tool jobs (CPU/mem/iface/ping per
	// host, on a cadence). Fed by transport.OnScheduledJobs from each
	// Register reply. Same out-channel as the adapters layer so the
	// downstream pipeline (gRPC StreamMetrics → WAL → Quarkus → TSDB) is uniform.
	// Built before config.reload so the executor can reference sched.Reload.
	sched := scheduler.New(ctx, log, registry, out)

	// checks.Runtime runs continuous self-metric collection on this host
	// (Local Agent mode D-12). Uses the shared out channel so metrics flow
	// through the same WAL → gRPC StreamMetrics path as scheduler and adapters.
	// linux.system check is auto-registered via init() in internal/checks.
	checksRuntime := checks.New(ctx, log, checks.Default, out)
	defer checksRuntime.Reload(nil) // graceful teardown on shutdown

	// Phase 5 — worker pools + jitter (collector.conf tunables).
	// Limita concorrência por kind (snmp/icmp) e espalha primeiro tick
	// pra evitar 100 walks SNMP no segundo 0. Default sensato em config.go.
	checksRuntime.SetWorkerPools(cfg.SNMPPollers, cfg.ICMPPingers)
	checksRuntime.SetJitter(cfg.CheckJitterMs)

	// Phase 3 Plan 4 — cardinality budget per host. Iniciado com o default
	// (10000); o budget real virá do RegisterResponse via OnCollectorConfig
	// quando o servidor expor o field 7 (Plan 06 fecha a UI de edição). Até
	// lá, o default protege contra explosão de DSLAM/switch core mesmo sem
	// configuração explícita.
	tagger := checks.NewTagger(config.DefaultTaggerBudget, log)
	checksRuntime.SetTagger(tagger)

	// Self-metrics: emite CPU/mem/disco/rede do PROPRIO host do agente, com
	// tag __self__=true. Independente do scheduler/checksRuntime — o operador
	// nao precisa configurar nada. Quarkus VmRemoteWriter reescreve nome
	// (agent_host_metric_<n>) e label (collector_id em vez de host_id).
	selfmetrics.Start(ctx, log, out, cfg.CollectorID, selfmetrics.DefaultInterval)

	// Canal global de Events emitidos por checks (snmp.autodiscover,
	// icmp.scan). Buffered pra absorver rajadas de candidates sem bloquear
	// o Runtime. Drenado pela goroutine StreamEvents dentro de
	// transport.RunForever — eventos viram EventBatch RPC.
	eventsCh := make(chan []*collectorv1.Event, 64)
	checks.SetEventsChannel(eventsCh)

	// OTLP receiver + forwarder. Recebe spans de pods Java instrumentados
	// pelo nosso javaagent (injetado via webhook do agent) na porta 4317,
	// converte pro nosso Span message e empacota em SpanBatch que viaja
	// via gRPC StreamSpans pro backend.
	//
	// Task 1 — trace durability: the otlp.Forwarder still aggregates raw spans
	// into SpanBatch values and pushes them onto spansCh, but a SpanProducer
	// now drains that channel and persists each batch to the span WAL BEFORE
	// the gRPC sender sees it (mirroring the metrics Producer→WAL→Sender path).
	// Spans therefore survive a backend restart or a multi-hour POP isolation
	// and replay on reconnect, instead of being dropped best-effort.
	spansCh := make(chan *collectorv1.SpanBatch, 32)
	otlpForwarder := otlp.NewForwarder(cfg.CollectorID, log, spansCh, 500, 5*time.Second)
	spanProducer := transport.NewSpanProducer(spanWAL, log)
	go spanProducer.Run(ctx, spansCh)
	otlpReceiver := otlp.NewReceiver(otlp.DefaultListenAddr, otlpForwarder, log)
	go func() {
		if err := otlpReceiver.Start(ctx); err != nil {
			log.Warn("otlp receiver stopped", "err", err)
		}
	}()
	go otlpForwarder.Run(ctx)

	// OTLP/HTTP receiver (porta 4318 por default). Mesmo Forwarder/sink do
	// gRPC — ambos os caminhos despejam no spansCh único. Habilitado por
	// default; desligar via ISPWATCH_OTLP_HTTP_DISABLE=1 caso operador prefira
	// só gRPC. Sem WAL — vide nota acima sobre best-effort tracing.
	if getenvOr("ISPWATCH_OTLP_HTTP_DISABLE", "0") != "1" {
		httpAddr := otlp.ParsePortOrDefault(getenvOr("ISPWATCH_OTLP_HTTP_PORT", ""))
		corsOrigins := otlp.ParseCORSOrigins(getenvOr("ISPWATCH_OTLP_HTTP_CORS_ORIGINS", "*"))
		otlpHTTP := otlp.NewHTTPReceiver(httpAddr, otlpForwarder, log, otlp.DefaultMaxBodyBytes, corsOrigins)
		go func() {
			if err := otlpHTTP.Start(ctx); err != nil {
				log.Warn("otlp http receiver stopped", "err", err)
			}
		}()
		// Self-metrics publisher: 30s tick → agent_otlp_http_requests_total
		// e agent_otlp_http_spans_total (+ per-endpoint/status). Mesmo
		// contrato do agent_ebpf_lost_samples (commit 26781ad). Cumulativo;
		// dashboards aplicam rate().
		go publishOtlpHTTPSelfMetrics(ctx, log, otlpHTTP, out, cfg.CollectorID)
	} else {
		log.Info("otlp http receiver disabled via ISPWATCH_OTLP_HTTP_DISABLE")
	}

	// eBPF L7 tracer (Phase 2). Carrega programas BPF que escutam
	// tcp_sendmsg/recvmsg + uprobes TLS, decodifica wire protocols
	// (Postgres, Redis, HTTP, MySQL, Mongo, etc.) e converte cada request
	// num span OTLP empurrado pro otlpForwarder. Default off — ativa via
	// ISPWATCH_EBPF_TRACING=1. Exige privileged + hostNetwork + hostPID
	// no DaemonSet (ver Helm chart).
	if getenvOr("ISPWATCH_EBPF_TRACING", "0") == "1" {
		startEbpfTracer(ctx, log, otlpForwarder, out, cfg.CollectorID)
	}

	// config.reload (D-22): server pushes a fresh config inline so we can
	// hot-swap without re-Register. Carries adapters[], scheduled_jobs[] and
	// checks[] — same callbacks transport.OnAdapters / OnScheduledJobs fire
	// from periodic Register replies, so "where is my new config applied"
	// stays a single code path regardless of trigger.
	// Server-driven config cache (Task 2). Persists the last-known-good config
	// to disk so the collector keeps polling its jobs across a backend restart
	// or a multi-hour POP isolation. Errors here are non-fatal — caching is an
	// availability optimization, not a correctness requirement.
	cfgCache, err := configcache.New(cfg.ConfigCachePath)
	if err != nil {
		log.Warn("config cache: init failed (continuing without cache)", "err", err)
		cfgCache = nil
	} else {
		log.Info("config cache: enabled", "path", cfg.ConfigCachePath)
	}

	checksReloadFn := func(cfgs []*collectorv1.CheckConfig) {
		log.Info("config.reload: applying check configs", "count", len(cfgs))
		// Keep-current-on-empty: a transient empty check list (backend
		// mid-restart) must not stop the running checks.
		checksRuntime.ReloadServerDriven(cfgs)
	}
	registry.Register(tools.NewConfigReload(runtime.Reload, sched.ReloadServerDriven, checksReloadFn))

	// Phase 5 — pull-based config loop. Substitui o caminho
	// push (config.reload via gRPC) por polling HTTP do servidor. Aplica
	// deltas via ApplyDelta no scheduler, sem stop-the-world.
	// Phase 5b — auth migrou de JWT estático (env AGENT_TOKEN) pra mTLS.
	// O cliente HTTP reaproveita o mesmo client cert + chave + trust bundle
	// já configurados pro gRPC, então o operador não precisa configurar nada
	// novo. Endpoint do servidor é derivado do gRPC endpoint trocando
	// :8443 → :8444 (porta HTTPS+mTLS dedicada do Quarkus REST).
	httpEndpoint := deriveHttpEndpoint(cfg.Server)

	// Quarkus /q/metrics scraper. Polla backend pra saber quais pods
	// estão marcados como mode=quarkus_metrics, resolve pod IP via
	// kubelet local e scrape periódico. Distribui trabalho entre
	// agents do DaemonSet: cada agent só vê pods do seu próprio nó.
	quarkusScraper := quarkus.New(httpEndpoint, cfg.TenantID, cfg.CollectorID,
		cfg.ClientCert, cfg.ClientKey, cfg.TrustBundle, out, log)
	go quarkusScraper.Run(ctx)

	pollInterval := time.Duration(cfg.ConfigPollSeconds) * time.Second
	// checks.SetBackend habilita checks a postarem dados de volta pro backend
	// usando o mesmo cert mTLS. Falha aqui não derruba o agent — checks
	// dependentes só vão errar no primeiro tick.
	if err := checks.SetBackend(httpEndpoint, cfg.TenantID, cfg.CollectorID,
		cfg.ClientCert, cfg.ClientKey, cfg.TrustBundle); err != nil {
		log.Warn("checks.SetBackend failed (ingestion will fail)", "err", err)
	}

	// journald → OTLP logs export. Default off; ativa via
	// ISPWATCH_LOGS_JOURNALD=1. Subprocess `journalctl -f` lê o journal
	// localmente, converte cada record pra OTLP LogRecord e POSTa em batches
	// pra /api/collector/v1/logs do backend usando o mesmo cert mTLS dos
	// outros canais. Sem WAL — best-effort, mesmo padrão de tracing.
	if getenvOr("ISPWATCH_LOGS_JOURNALD", "0") == "1" {
		startJournaldLogs(ctx, log, httpEndpoint, cfg, out)
	} else {
		log.Debug("journald logs disabled (set ISPWATCH_LOGS_JOURNALD=1 to enable)")
	}

	// Docker container logs → OTLP logs export. Default off; ativa via
	// ISPWATCH_LOGS_DOCKER=1. Descobre containers via Docker SDK, taila
	// json-file logs de cada um, parseia e POSTa em batches pro backend
	// usando o mesmo LogsExporter/endpoint do journald.
	if getenvOr("ISPWATCH_LOGS_DOCKER", "0") == "1" {
		startDockerLogs(ctx, log, httpEndpoint, cfg, out)
	} else {
		log.Debug("docker logs disabled (set ISPWATCH_LOGS_DOCKER=1 to enable)")
	}

	// Phase k8s — quando agent roda como DaemonSet, NODE_NAME env existe
	// (downward API). Reporta identidade pro backend pra criar noc_host +
	// hostcheck k8s.kubelet idempotente. No-op em bare-metal/docker-compose.
	autoRegisterK8sIfNeeded(ctx, log, httpEndpoint,
		cfg.ClientCert, cfg.ClientKey, cfg.TrustBundle)
	go func() {
		err := configpull.Run(ctx, configpull.Config{
			Endpoint:     httpEndpoint,
			TenantID:     cfg.TenantID,
			CollectorID:  cfg.CollectorID,
			ClientCert:   cfg.ClientCert,
			ClientKey:    cfg.ClientKey,
			TrustBundle:  cfg.TrustBundle,
			PollInterval: pollInterval,
			Logger:       log,
		}, checksRuntime)
		if err != nil {
			log.Error("config pull loop exited", "err", err)
		}
	}()

	// LLDP discovery runner (Phase 2 bootstrap). Goroutine started before
	// transport so the SetSender callback in OnTopologySender wires it up
	// the moment the first Register completes. When -lldp-interval==0 the
	// runner.Run returns immediately.
	lldpRunner := buildLldpRunner(cfg, log)
	if lldpRunner != nil {
		go func() {
			if err := lldpRunner.Run(ctx); err != nil {
				log.Error("lldp runner exited", "err", err)
			}
		}()
	}

	// applyServerConfig fans a full CollectorConfig out to the three runtimes
	// using their KEEP-CURRENT-ON-EMPTY entrypoints (Task 2). Empty lists leave
	// the corresponding runtime untouched, so a transient empty generation
	// during a backend restart never stops collection.
	applyServerConfig := func(c *collectorv1.CollectorConfig, src string) {
		if c == nil {
			return
		}
		log.Info("applying server config",
			"source", src,
			"adapters", len(c.GetAdapters()),
			"scheduled_jobs", len(c.GetScheduledJobs()),
			"checks", len(c.GetChecks()),
		)
		runtime.Reload(c.GetAdapters())
		sched.ReloadServerDriven(c.GetScheduledJobs())
		checksRuntime.ReloadServerDriven(c.GetChecks())
	}

	// Startup: load the last-known-good config and apply it immediately so the
	// collector resumes polling without waiting for the server to come back
	// (Task 2 — survive a backend that is down at boot).
	if cfgCache != nil {
		if cached, lerr := cfgCache.Load(); lerr != nil {
			log.Warn("config cache: load failed", "err", lerr)
		} else if configcache.IsNonEmpty(cached) {
			log.Info("config cache: applying cached config on startup (backend not yet contacted)")
			applyServerConfig(cached, "cache")
		} else {
			log.Info("config cache: no cached config yet (first boot or never persisted)")
		}
	}

	transport.RunForever(ctx, log, transport.RunOpts{
		Server:      cfg.Server,
		ClientCert:  cfg.ClientCert,
		ClientKey:   cfg.ClientKey,
		TrustBundle: cfg.TrustBundle,
		TenantID:    cfg.TenantID,
		CollectorID: cfg.CollectorID,
		Version:     Version,
		// WAL-backed metric stream (Plan 5, D-06 always-on).
		// RunForever reconnects on stream error; each reconnect replays the WAL
		// to deliver any unacked batches (gate D-10).
		WAL:       walDB,
		WALNotify: producer.Notify(),
		Events:    eventsCh,
		// WAL-backed span stream (Task 1). Replays buffered traces on reconnect.
		SpanWAL:       spanWAL,
		SpanWALNotify: spanProducer.Notify(),
		Tools:         registry,
		// OnConfig persists the last-known-good full config (Task 2). Fires
		// before the per-list callbacks; the cache no-ops on an empty config
		// so a transient empty generation never clobbers a good cache.
		OnConfig: func(c *collectorv1.CollectorConfig) {
			if cfgCache == nil {
				return
			}
			if configcache.IsNonEmpty(c) {
				if serr := cfgCache.Save(c); serr != nil {
					log.Warn("config cache: save failed", "err", serr)
				} else {
					log.Debug("config cache: persisted last-known-good config")
				}
			}
		},
		// t2-7.F.2: server-driven adapter instantiation. Each Register reply
		// carries the adapter list as configured in the UI. KEEP-CURRENT-ON-EMPTY
		// applies: an empty list leaves the running adapters alone.
		OnAdapters:      runtime.Reload,
		OnScheduledJobs: sched.ReloadServerDriven,
		OnTopologySender: func(send transport.TopologySender) {
			// Fanout: o mesmo gRPC sender alimenta tanto o discovery LLDP-SNMP
			// (runner standalone) quanto os tools agendados que retornam
			// result["topology_edges"] (ex: mikrotik.discover_topology).
			if lldpRunner != nil {
				lldpRunner.SetSender(lldp.Sender(send))
			}
			if sched != nil {
				sched.SetTopologySender(scheduler.TopologySender(send))
			}
		},
	})

	log.Info("collector stopped cleanly")
}

// adapterRuntime owns the lifecycle of all running adapter goroutines for a
// single collector process. Reload cancels the previous batch, builds the
// new one from the server-supplied AdapterConfig list, and starts them under
// a fresh per-generation context.
//
// The full-restart-on-reload design is intentional: hot-reloading a single
// adapter's config (intervals, credentials) is hairy — torn down and rebuilt
// is correct by construction and matches how the rest of the system models
// "topology changed: rediscover everything".
type adapterRuntime struct {
	parent context.Context
	log    *slog.Logger
	out    chan<- []*collectorv1.Metric
	cfg    *config.Config

	mu        sync.Mutex
	cancel    context.CancelFunc // cancels current generation's ctx
	wg        *sync.WaitGroup    // waits for current generation's goroutines
	bootstrap bool               // true until first server-driven Reload
}

func newAdapterRuntime(parent context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, cfg *config.Config) *adapterRuntime {
	return &adapterRuntime{
		parent:    parent,
		log:       log,
		out:       out,
		cfg:       cfg,
		bootstrap: true,
	}
}

// Reload swaps the running adapter set for the one the server just sent.
// KEEP-CURRENT-ON-EMPTY (Task 2): an empty list is treated as "server has no
// opinion / transient empty during a backend restart" — the running adapters
// are LEFT RUNNING so collection never stops. The wire (AdapterConfig in
// RegisterResponse) carries no generation number or intentional-empty flag, so
// a transient empty (Quarkus mid-restart) is indistinguishable from an
// operator genuinely clearing all adapters; we default to keep-current and log
// loudly. The whole running set is still torn down and rebuilt on the parent
// ctx cancellation (shutdown).
func (r *adapterRuntime) Reload(list []*collectorv1.AdapterConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(list) == 0 {
		if r.bootstrap {
			r.log.Info("server returned no adapters — nothing to start in this generation")
		} else {
			r.log.Warn("adapter reload: empty generation from server — KEEPING current adapters running (keep-current-on-empty; wire has no intentional-empty flag)")
		}
		return
	}
	r.bootstrap = false

	kinds := make([]string, len(list))
	for i, a := range list {
		kinds[i] = a.GetKind()
	}
	r.log.Info("adapter reload requested by server", "count", len(list), "kinds", kinds)

	// Cancel previous generation and wait for its goroutines to drain. This
	// keeps the lifecycle deterministic — the new generation only starts
	// pushing into `out` after the old one has stopped, so we don't have two
	// adapters of the same kind double-polling during the swap.
	if r.cancel != nil {
		r.cancel()
		if r.wg != nil {
			r.wg.Wait()
		}
		r.cancel = nil
		r.wg = nil
	}

	// Build the new generation, skipping (with a WARN) any kind we don't
	// know or any params validation error — one bad config shouldn't take
	// down the others.
	built := make([]adapters.Adapter, 0, len(list))
	for _, ac := range list {
		a, err := adapters.Build(ac.GetKind(), ac.GetParams(), r.log)
		if err != nil {
			r.log.Warn("skipping adapter from server config",
				"kind", ac.GetKind(), "err", err)
			continue
		}
		built = append(built, a)
	}

	r.startLocked(built)
}

// startLocked must be called with r.mu held. Spawns one goroutine per
// adapter under a fresh ctx so Reload can later cancel the whole generation
// in one shot.
func (r *adapterRuntime) startLocked(list []adapters.Adapter) {
	if len(list) == 0 {
		r.log.Info("no adapters to run for this generation")
		return
	}
	ctx, cancel := context.WithCancel(r.parent)
	wg := &sync.WaitGroup{}
	for _, a := range list {
		wg.Add(1)
		go func(a adapters.Adapter) {
			defer wg.Done()
			r.log.Info("adapter starting", "name", a.Name())
			if err := a.Run(ctx, r.out); err != nil {
				r.log.Error("adapter exited", "name", a.Name(), "err", err)
			} else {
				r.log.Info("adapter exited cleanly", "name", a.Name())
			}
		}(a)
	}
	r.cancel = cancel
	r.wg = wg
}

// buildLldpRunner cria o runner LLDP a partir da config CLI. Devolve nil
// quando o discovery não foi habilitado (-lldp-interval == 0 ou
// -lldp-targets vazio). O wire-up do sender acontece no OnTopologySender
// depois que o transport completar o primeiro Register.
func buildLldpRunner(cfg *config.Config, log *slog.Logger) *lldp.Runner {
	if !cfg.LldpEnabled() {
		return nil
	}
	parsed := cfg.ParseLldpTargets()
	if len(parsed) == 0 {
		log.Warn("lldp enabled but no valid targets parsed (expected host_id@address[:port])",
			"raw", cfg.LldpTargets)
		return nil
	}
	targets := make([]lldp.Target, len(parsed))
	for i, t := range parsed {
		targets[i] = lldp.Target{
			HostId:    t.HostId,
			Address:   t.Address,
			Community: cfg.LldpCommunity,
		}
	}
	log.Info("lldp discovery enabled", "targets", len(targets), "interval", cfg.LldpInterval)
	return lldp.NewRunner(
		lldp.Options{
			CollectorId: cfg.CollectorID,
			Targets:     targets,
			Interval:    cfg.LldpInterval,
			Timeout:     cfg.LldpTimeout,
		},
		log.With("subsystem", "lldp"),
		newGoSnmpClient,
	)
}

// newGoSnmpClient é a ClientFactory que devolve um SnmpClient real (gosnmp).
// Mora no main.go pra evitar acoplar internal/discovery/lldp ao gosnmp; a
// interface lldp.SnmpClient é mockável em teste.
func newGoSnmpClient(target, community string, timeout time.Duration) lldp.SnmpClient {
	host, port := splitHostPort(target)
	return &gosnmpClient{
		target: fmt.Sprintf("%s:%d", host, port),
		host:   host,
		snmp: &gosnmp.GoSNMP{
			Target:    host,
			Port:      port,
			Community: community,
			Version:   gosnmp.Version2c,
			Timeout:   timeout,
			Retries:   1,
			MaxOids:   gosnmp.MaxOids,
		},
	}
}

func splitHostPort(target string) (string, uint16) {
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			host := target[:i]
			var port uint16
			_, err := fmt.Sscanf(target[i+1:], "%d", &port)
			if err == nil && port > 0 {
				return host, port
			}
			return target, 161
		}
	}
	return target, 161
}

type gosnmpClient struct {
	target string
	host   string
	snmp   *gosnmp.GoSNMP
}

func (c *gosnmpClient) connect() error {
	if c.snmp.Conn != nil {
		return nil
	}
	return c.snmp.Connect()
}

func (c *gosnmpClient) Walk(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.snmp.Conn.SetDeadline(dl)
	}
	var out []gosnmp.SnmpPDU
	err := c.snmp.BulkWalk(root, func(pdu gosnmp.SnmpPDU) error {
		out = append(out, pdu)
		return nil
	})
	return out, err
}

func (c *gosnmpClient) Host() string { return c.host }

func (c *gosnmpClient) Close() {
	if c.snmp != nil && c.snmp.Conn != nil {
		_ = c.snmp.Conn.Close()
	}
}

// runIngestMode roda o agent no modelo "Datadog" (API key): recebe OTLP de
// apps locais e emite as métricas do próprio host, encaminhando tudo pro
// gateway /api/ingest/v1 com Bearer token — sem enrollment, sem mTLS, sem
// cert por agent. É o caminho simples; o modo gRPC mTLS (main) segue intacto.
// ebpfStatsSink recebe os spans que o bridge eBPF gera a partir do tráfego de
// fio (HTTP/gRPC/Postgres/Redis/…) e os despeja no MESMO concentrator dos spans
// instrumentados, alimentando os golden signals (hits/erros/latência) que vão
// pro /api/ingest/v1/apm/stats. Higieniza cada span (obfuscate) antes de contar,
// igual o tap do receiver OTLP (rec.SetAPMTap). De propósito NÃO encaminha o
// span cru: o caminho legado fazia isso sem sampling e inundava noc_span; os
// golden signals já contam 100% do tráfego, então a lente de serviço acende pra
// apps não-instrumentadas sem custo de armazenamento de rastro.
type ebpfStatsSink struct{ conc *concentrator.Concentrator }

func (s ebpfStatsSink) Push(spans []*collectorv1.Span) {
	for _, sp := range spans {
		obfuscate.Apply(sp)
		// Carimba a origem ANTES do Add: o concentrator copia isso pro stat
		// (source=ebpf), o backend grava a coluna e o catálogo mostra o badge
		// "eBPF / sem instrumentação". Estilo Datadog USM. Posto depois do
		// obfuscate pra não ser higienizado fora.
		if sp.Attributes == nil {
			sp.Attributes = map[string]string{}
		}
		sp.Attributes[concentrator.SourceAttr] = "ebpf"
		s.conc.Add(sp)
	}
}

func runIngestMode(ingestURL string) {
	log := newLogger(getenvOr("COLLECTOR_LOG_LEVEL", "info"))
	token := strings.TrimSpace(os.Getenv("ISPWATCH_INGEST_TOKEN"))
	if token == "" {
		log.Error("ingest mode: ISPWATCH_INGEST_TOKEN ausente")
		os.Exit(1)
	}
	hostID := strings.TrimSpace(getenvOr("ISPWATCH_NODE_NAME", getenvOr("NODE_NAME", "")))
	if hostID == "" {
		hostID, _ = os.Hostname()
	}
	cluster := strings.TrimSpace(os.Getenv("ISPWATCH_CLUSTER"))

	log.Info("ispwatch collector starting (ingest mode)",
		"version", Version, "endpoint", ingestURL, "host", hostID, "cluster", cluster)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("signal received, shutting down", "signal", s.String())
		cancel()
	}()

	exporter := otlp.NewIngestExporter(ingestURL, token, hostID, cluster, log)

	// Métricas do próprio host (CPU/mem/disco/rede) → OTLP /metrics.
	out := make(chan []*collectorv1.Metric, 256)
	selfmetrics.Start(ctx, log, out, hostID, selfmetrics.DefaultInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ms := <-out:
				if err := exporter.PostMetrics(ctx, ms); err != nil {
					log.Warn("ingest metrics failed", "err", err, "count", len(ms))
				}
			}
		}
	}()

	// Runtime (JVM): scrape /q/metrics dos workloads marcados como
	// quarkus_metrics (aba Runtime). Certless/Bearer; busca a lista no gateway
	// e casa por workload (sobrevive a restart de pod). Só em nós k8s. Publica
	// pelo mesmo `out` (→ PostMetrics Bearer).
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "k8s.node") {
		qs := quarkus.NewCertless(ingestURL, token, hostID, out, log)
		go qs.Run(ctx)
	}

	// k8s: registra o nó (→ noc_host + check k8s.kubelet, aparece em
	// "Aplicações") e roda o kubelet check LOCAL (pods/containers/node) com o
	// host_id retornado. Mesma coleta do agent completo — só o envio muda
	// (OTLP+Bearer em vez de gRPC mTLS).
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "k8s.node") {
		nodeIP := strings.TrimSpace(getenvOr("NODE_IP", ""))
		nodeHostID, err := exporter.RegisterK8sNode(ctx, cluster, hostID, nodeIP, "")
		if err != nil {
			log.Warn("k8s register falhou — sigo só com métricas de host", "err", err)
		} else {
			log.Info("k8s node registrado", "host_id", nodeHostID, "node", hostID)
			startKubeletCheck(ctx, log, out, nodeHostID)

			// Vulnerabilidade de aplicação (camada 2/3, toggle): Trivy gera o SBOM
			// das imagens rodando no nó e o agente manda só a lista pro gateway.
			if getenvOr("ISPWATCH_SBOM_SCAN", "0") == "1" {
				startSbomScan(ctx, log, exporter, nodeHostID)
			} else {
				log.Debug("sbom scan desativado (set ISPWATCH_SBOM_SCAN=1 pra habilitar)")
			}
		}
	}

	// Cluster Agent (modo k8s.cluster, 1 réplica): fala com o API server
	// in-cluster e faz LIST periódico dos Events do cluster inteiro (OOMKilled,
	// BackOff, FailedScheduling, Unhealthy…) → push certless pro noc_k8s_event
	// (timeline na cluster page). É a visão cross-node que o DaemonSet (kubelet
	// local) não alcança. RBAC dedicado -cluster (events get/list/watch).
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "k8s.cluster") {
		apiURL := strings.TrimSpace(getenvOr("ISPWATCH_K8S_API_URL", ""))
		if apiURL == "" {
			if h := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")); h != "" {
				apiURL = "https://" + h + ":" + getenvOr("KUBERNETES_SERVICE_PORT", "443")
			}
		}
		if apiURL == "" {
			log.Warn("k8s.cluster: KUBERNETES_SERVICE_HOST ausente — cluster-agent desativado (fora de um cluster?)")
		} else {
			interval := 30 * time.Second
			if v := strings.TrimSpace(getenvOr("ISPWATCH_CLUSTER_INTERVAL_SEC", "")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					interval = time.Duration(n) * time.Second
				}
			}
			eventLimit := 0
			if v := strings.TrimSpace(getenvOr("ISPWATCH_CLUSTER_EVENT_LIMIT", "")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					eventLimit = n
				}
			}
			caCfg := clusteragent.Config{
				APIServerURL:  apiURL,
				TokenFile:     getenvOr("ISPWATCH_K8S_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
				CAFile:        getenvOr("ISPWATCH_K8S_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
				Insecure:      getenvOr("ISPWATCH_K8S_INSECURE", "0") == "1",
				Cluster:       cluster,
				Interval:      interval,
				IncludeNormal: getenvOr("ISPWATCH_CLUSTER_EVENTS_INCLUDE_NORMAL", "0") == "1",
				EventLimit:    eventLimit,
			}
			if ca, err := clusteragent.New(caCfg, exporter, log); err != nil {
				log.Error("k8s.cluster: cluster-agent init falhou", "err", err)
			} else {
				go ca.Run(ctx)
				log.Info("k8s.cluster: cluster-agent ativo (watch de eventos do API server)", "api", apiURL)
			}
		}
	}

	// Receiver OTLP/HTTP (4318): apps locais mandam spans/metrics/logs e o
	// agent encaminha o corpo cru pro gateway com o Bearer token.
	httpAddr := otlp.ParsePortOrDefault(getenvOr("ISPWATCH_OTLP_HTTP_PORT", ""))
	corsOrigins := otlp.ParseCORSOrigins(getenvOr("ISPWATCH_OTLP_HTTP_CORS_ORIGINS", "*"))
	rec := otlp.NewHTTPReceiver(httpAddr, nil, log, otlp.DefaultMaxBodyBytes, corsOrigins)
	rec.SetForwardRaw(func(signal, ct string, body []byte) error {
		return exporter.PostRaw(ctx, signal, ct, body)
	})

	// Item 1 — carimbo de pod/namespace por IP de origem (origin-detection
	// estilo Datadog / k8sattributes do OTel): spans de apps auto-instrumentadas
	// que NÃO anunciam k8s.namespace.name/k8s.pod.name passam a cair no pod certo.
	// Independe do eBPF (vale com tracing eBPF desligado). Só em nós k8s, onde o
	// kubelet local lista os pods e seus IPs; em bare-metal não há o que resolver.
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "k8s.node") {
		kubeletURL := getenvOr("ISPWATCH_KUBELET_URL", "https://localhost:10250")
		tokenFile := getenvOr("ISPWATCH_KUBELET_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
		caFile := getenvOr("ISPWATCH_KUBELET_CA_FILE", "")
		insecure := getenvOr("ISPWATCH_KUBELET_INSECURE", "1") == "1"
		if resolver, err := ebpf.NewPodResolver(kubeletURL, tokenFile, caFile, insecure, log); err != nil {
			log.Warn("otlp: pod stamping desativado (spans sem pod salvo se a app anunciar)", "err", err)
		} else {
			go resolver.Run(ctx)
			rec.SetPodResolver(resolver)
			log.Info("otlp: carimbo de pod/namespace por IP de origem ativo (kubelet)")

			// Detecção de linguagem por processo (estilo Datadog): olha /proc,
			// mapeia pid→pod pelo mesmo resolver e reporta a linguagem por pod
			// pro gateway. O backend usa pra mostrar o botão de auto-injeção
			// (Java) em apps caixa-preta que ainda não emitem telemetria.
			if getenvOr("ISPWATCH_LANG_DETECT", "1") != "0" {
				det := langdetect.New(resolver, exporter, log)
				go det.Run(ctx)
				log.Info("langdetect: detecção de linguagem por processo ativa")
			}

			// Profiler de CPU eBPF (Opção B, toggle): amostra a pilha de CPU de
			// TODOS os processos do nó (perf_event + stack traces) e atribui ao
			// serviço pelo mesmo resolver. Coleção eBPF SEPARADA do tracer L7 — se
			// o verifier rejeitar num kernel, só o profiler fica off; o L7 nunca é
			// tocado. source="ebpf"; o JFR cobre Java. Exige privileged+hostPID (já
			// requeridos pelo L7). No S1, só loga o resumo por serviço.
			if getenvOr("ISPWATCH_PROFILING_ENABLED", "0") == "1" {
				startEbpfProfiler(ctx, log, exporter, resolver)
				log.Info("cpuprofiler: profiling de CPU eBPF ativo")
			} else {
				log.Debug("cpuprofiler desativado (set ISPWATCH_PROFILING_ENABLED=1 pra habilitar)")
			}
		}
	}

	// Trace-agent (Datadog-style): resume os spans NA BORDA. O corpo cru segue
	// sendo repassado normalmente; em paralelo, cada span é higienizado e
	// contado num DDSketch por bucket de 10s, e o resumo (hits/errors/latência
	// exatos) vai pro /api/ingest/v1/apm/stats. Não-destrutivo: nada de span se
	// perde; só passa a existir a métrica agregada.
	apmConc := concentrator.New(log)
	apmStats := statsfwd.New(nil, ingestURL, token, Version, log)
	rec.SetAPMTap(func(spans []*collectorv1.Span) {
		for _, s := range spans {
			obfuscate.Apply(s)
			apmConc.Add(s)
		}
	})
	// Sampler (igual ao Datadog): guarda todo erro + todo trace lento (>2s) +
	// uma amostra de 10% dos normais; o resto NÃO é encaminhado em detalhe. As
	// stats acima já contam 100%, então os números seguem exatos.
	apmSampler := sampler.New(0.10, 2*time.Second)
	rec.SetTraceSampler(apmSampler.KeepRaw)
	go func() {
		t := time.NewTicker(concentrator.BucketDuration)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = apmStats.Send(context.Background(), apmConc.Flush()) // best-effort no shutdown
				return
			case <-t.C:
				if err := apmStats.Send(ctx, apmConc.Flush()); err != nil {
					log.Warn("apm stats flush failed", "err", err)
				}
			}
		}
	}()

	// eBPF L7 tracer no modo ingest (Frente 4 — observabilidade zero-código).
	// Escuta o tráfego de fio (HTTP/gRPC/Postgres/Redis/…) de QUALQUER app sem
	// instrumentar e alimenta o mesmo concentrator acima → a lente de serviço
	// acende com golden signals pra apps não-instrumentadas. Histórico: o tracer
	// só estava ligado no caminho legado gRPC (func main); aqui é o modo certless
	// que roda em produção. Toggle ISPWATCH_EBPF_TRACING=1 (exige
	// privileged+hostNetwork+hostPID no DaemonSet). Sem o toggle, no-op.
	//
	// Roda em goroutine de PROPÓSITO: tracer.Run() carrega ~14 programas BPF e
	// pode demorar (ou travar em kernel novo) — NÃO pode bloquear o resto do
	// startup, em especial o rec.Start() (receiver OTLP :4318) lá embaixo. É o
	// mesmo padrão do caminho legado, onde os receivers sobem em goroutine ANTES
	// do tracer. Best-effort: se o eBPF falhar, o agent segue normal.
	if getenvOr("ISPWATCH_EBPF_TRACING", "0") == "1" {
		go startEbpfTracer(ctx, log, ebpfStatsSink{conc: apmConc}, out, hostID)
	}

	// Coleta de logs (toggle, estilo Datadog): taila /var/log/pods (CRI) e
	// encaminha cada linha como OTLP JSON + Bearer pro gateway /api/ingest/v1/logs.
	if getenvOr("ISPWATCH_LOGS_ENABLED", "0") == "1" {
		startIngestPodLogs(ctx, log, exporter, hostID)
	} else {
		log.Debug("pod logs desativados (set ISPWATCH_LOGS_ENABLED=1 pra habilitar)")
	}

	// SNMP traps (toggle, B2): receptor UDP/162 que encaminha traps do device pro
	// backend (/api/ingest/v1/snmptrap) — o device avisa na hora, sem esperar o poll.
	if getenvOr("ISPWATCH_SNMP_TRAPS_ENABLED", "0") == "1" {
		startSnmpTrapListener(ctx, log, exporter)
	} else {
		log.Debug("snmp traps desativados (set ISPWATCH_SNMP_TRAPS_ENABLED=1 pra habilitar)")
	}

	// Checagens agendadas (config-pull): registra o collector e puxa os checks
	// que o usuário criou no painel, executando cada um no intervalo. O resultado
	// vai pelo mesmo canal `out` (PostMetrics entrega). Reusa a máquina mTLS.
	if getenvOr("ISPWATCH_CHECKS_ENABLED", "1") == "1" {
		startIngestChecks(ctx, log, exporter, token, ingestURL, hostID, out)
	} else {
		log.Debug("checagens agendadas desativadas (set ISPWATCH_CHECKS_ENABLED=1 pra habilitar)")
	}

	if err := rec.Start(ctx); err != nil {
		log.Error("ingest mode: otlp http receiver falhou", "err", err)
		os.Exit(1)
	}
}

// startIngestPodLogs monta o pipeline de logs de pod no modo ingest: um
// LogsExporter certless (batch → OTLP JSON + Bearer) + o tailer CRI. Exclui o
// próprio namespace do agent (POD_NAMESPACE) e os de ISPWATCH_LOGS_EXCLUDE_NAMESPACES
// pra evitar loop de logs.
func startIngestPodLogs(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, hostID string) {
	logsExp := otlp.NewIngestLogsExporter(exporter, log)

	exclude := []string{}
	if self := strings.TrimSpace(getenvOr("POD_NAMESPACE", "")); self != "" {
		exclude = append(exclude, self)
	}
	for _, ns := range strings.Split(getenvOr("ISPWATCH_LOGS_EXCLUDE_NAMESPACES", ""), ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			exclude = append(exclude, ns)
		}
	}

	cursorPath := getenvOr("ISPWATCH_LOGS_CURSOR_PATH", "/var/lib/ispwatch-collector/log_cursors.json")
	tailer := logs.NewCRILogsTailer(logsExp, cursorPath, hostID, exclude, log)

	// Unified service tagging (igual Datadog): o service do log vem da label
	// tags.datadoghq.com/service do pod (lida do kubelet /pods), pra bater com o
	// service dos traces. Sem resolver/label, o tailer usa o nome do workload.
	kubeletURL := getenvOr("ISPWATCH_KUBELET_URL", "https://localhost:10250")
	tokenFile := getenvOr("ISPWATCH_KUBELET_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	caFile := getenvOr("ISPWATCH_KUBELET_CA_FILE", "")
	insecure := getenvOr("ISPWATCH_KUBELET_INSECURE", "1") == "1"
	if resolver, err := ebpf.NewPodResolver(kubeletURL, tokenFile, caFile, insecure, log); err != nil {
		log.Warn("logs: service tagging por label desativado (usando nome do workload)", "err", err)
	} else {
		go resolver.Run(ctx)
		tailer.SetServiceResolver(resolver)
		log.Info("logs: unified service tagging ativo (label tags.datadoghq.com/service)")
	}

	go logsExp.Run(ctx)
	go tailer.Run(ctx)
	log.Info("pod logs habilitados (CRI tailer)", "cursor", cursorPath, "exclude_ns", strings.Join(exclude, ","))
}

// startSbomScan liga o scanner de vulnerabilidade de aplicação (camada 2/3):
// embute o Trivy (geração de SBOM, sem banco de CVE), lista as imagens rodando
// no nó via kubelet /pods e manda a lista de componentes pro gateway (/sbom).
// Tudo configurável por env (sem rebuild): intervalo, args do trivy, socket do
// containerd. host_id = o do nó registrado (∈ tenant).
func startSbomScan(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, hostID string) {
	exclude := []string{}
	if self := strings.TrimSpace(getenvOr("POD_NAMESPACE", "")); self != "" {
		exclude = append(exclude, self)
	}

	interval := time.Hour
	if v := strings.TrimSpace(getenvOr("ISPWATCH_SBOM_INTERVAL", "")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	var extraArgs []string
	if v := strings.TrimSpace(getenvOr("ISPWATCH_SBOM_TRIVY_ARGS", "")); v != "" {
		extraArgs = strings.Fields(v)
	}

	sc, err := sbom.New(sbom.Config{
		HostID:            hostID,
		KubeletURL:        getenvOr("ISPWATCH_KUBELET_URL", "https://localhost:10250"),
		KubeletTokenFile:  getenvOr("ISPWATCH_KUBELET_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		KubeletCAFile:     getenvOr("ISPWATCH_KUBELET_CA_FILE", ""),
		KubeletInsecure:   getenvOr("ISPWATCH_KUBELET_INSECURE", "1") == "1",
		TrivyPath:         getenvOr("ISPWATCH_SBOM_TRIVY_PATH", "trivy"),
		ExtraTrivyArgs:    extraArgs,
		ContainerdAddr:    getenvOr("ISPWATCH_SBOM_CONTAINERD_ADDR", "/run/containerd/containerd.sock"),
		ContainerdNS:      getenvOr("ISPWATCH_SBOM_CONTAINERD_NS", "k8s.io"),
		Interval:          interval,
		ExcludeNamespaces: exclude,
	}, exporter, log)
	if err != nil {
		log.Warn("sbom scan desativado (init falhou)", "err", err)
		return
	}
	go sc.Run(ctx)
	log.Info("sbom scan habilitado (Trivy → SBOM por imagem)", "interval", interval.String())
}

// startIngestChecks liga o config-pull no modo ingest: registra o collector
// (Bearer) pra obter collector_id+tenant, monta um checks.Runtime emitindo no
// mesmo canal `out`, e roda o loop de config-pull com um client que injeta o
// Bearer token. Reusa toda a máquina de checks/scheduler do modo mTLS.
func startIngestChecks(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, token, ingestURL, hostID string, out chan<- []*collectorv1.Metric) {
	name := strings.TrimSpace(hostID)
	if name == "" {
		name, _ = os.Hostname()
	}
	collectorID, tenantID, err := exporter.RegisterCollector(ctx, name, []string{"metrics", "checks"})
	if err != nil {
		log.Warn("checks: registro de collector falhou — config-pull desativado", "err", err)
		return
	}
	if collectorID == "" {
		log.Warn("checks: collector_id vazio do register — config-pull desativado")
		return
	}

	// Heartbeat: re-registra o collector a cada 60s pra manter o last_seen fresco.
	// O backend deriva online/offline de noc_collector.last_seen, e SÓ o
	// /collector/register o atualiza (config-pull e POST de métricas não tocam).
	// Sem isso o collector vira "offline" após ~120s mesmo coletando normalmente.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, _, err := exporter.RegisterCollector(ctx, name, []string{"metrics", "checks"}); err != nil {
					log.Debug("heartbeat: re-registro do collector falhou", "err", err)
				}
			}
		}
	}()

	// Base raiz do servidor (config-pull fica em /api/collector/v1/config, fora
	// do /api/ingest/v1).
	base := strings.TrimRight(strings.TrimSpace(ingestURL), "/")
	base = strings.TrimRight(strings.TrimSuffix(base, "/api/ingest/v1"), "/")

	runtime := checks.New(ctx, log, checks.Default, out)
	checks.SetDeviceMetadataPusher(exporter)
	checks.SetDeviceConfigPusher(exporter) // NCM: check device.config_backup manda a running-config coletada
	runtime.SetWorkerPools(5, 10)
	runtime.SetJitter(1000)
	runtime.SetTagger(checks.NewTagger(config.DefaultTaggerBudget, log))

	pollSecs := 15
	if v := strings.TrimSpace(getenvOr("ISPWATCH_CHECKS_POLL_SECONDS", "")); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			pollSecs = n
		}
	}

	bearerClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: bearerRoundTripper{token: token, rt: http.DefaultTransport},
	}

	go func() {
		if err := configpull.Run(ctx, configpull.Config{
			Endpoint:     base,
			CollectorID:  collectorID,
			TenantID:     tenantID,
			PollInterval: time.Duration(pollSecs) * time.Second,
			HTTPClient:   bearerClient,
			Logger:       log,
		}, runtime); err != nil {
			log.Warn("config pull (ingest) encerrou", "err", err)
		}
	}()
	log.Info("checagens agendadas habilitadas (config-pull)",
		"collector_id", collectorID, "tenant", tenantID, "base", base, "poll_s", pollSecs)
}

// bearerRoundTripper injeta Authorization: Bearer <token> em cada request —
// usado pelo client de config-pull no modo ingest (sem mTLS).
type bearerRoundTripper struct {
	token string
	rt    http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+b.token)
	return b.rt.RoundTrip(r2)
}

// startKubeletCheck roda o check k8s.kubelet LOCALMENTE (sem depender do
// servidor mandar a config via config-pull), emitindo métricas de
// node/pod/container pro channel out com host_id = id do noc_host registrado
// (pra bater no filtro do drill de pods: k8s_pod_*{host_id="..."}).
func startKubeletCheck(ctx context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, hostID string) {
	factory, ok := checks.Default.Get("k8s.kubelet")
	if !ok {
		log.Warn("kubelet check factory ausente")
		return
	}
	insecure := "false"
	if getenvOr("ISPWATCH_KUBELET_INSECURE", "1") == "1" {
		insecure = "true"
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "k8s.kubelet-" + hostID,
		CheckType: "k8s.kubelet",
		HostId:    hostID,
		Enabled:   true,
		Interval:  durationpb.New(15 * time.Second),
		Params: map[string]string{
			"kubelet_url":          getenvOr("ISPWATCH_KUBELET_URL", "https://localhost:10250"),
			"token_file":           getenvOr("ISPWATCH_KUBELET_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
			"insecure_skip_verify": insecure,
		},
	}
	chk, err := factory(cfg)
	if err != nil {
		log.Warn("kubelet check factory error", "err", err)
		return
	}
	clog := log.With("component", "k8s-kubelet", "host_id", hostID)
	go func() {
		runOnce := func() {
			ms, err := chk.Run(ctx)
			if err != nil {
				clog.Debug("kubelet check run error", "err", err)
				return
			}
			if len(ms) == 0 {
				return
			}
			select {
			case out <- ms:
			case <-ctx.Done():
			default:
				clog.Warn("kubelet out channel full, dropping", "count", len(ms))
			}
		}
		runOnce()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runOnce()
			}
		}
	}()
	clog.Info("kubelet check started (local)", "interval", "15s")
}

func getenvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing required env var: %s\n", key)
		os.Exit(1)
	}
	return v
}

// startEbpfTracer carrega programas BPF e inicia o bridge Event→Span.
// Tudo best-effort: se algum passo falhar, loga e segue sem tracer (agent
// continua funcionando pra métricas/eventos).
//
// Requisitos no node: kernel >= 5.10 com BTF (vmlinux.h vem embeddado no
// .o), hostNetwork=true e hostPID=true no DaemonSet, securityContext.
// privileged=true ou capabilities {SYS_ADMIN,NET_ADMIN,BPF}.
func startEbpfTracer(ctx context.Context, log *slog.Logger, sink ebpf.SpanSink, metricsOut chan<- []*collectorv1.Metric, collectorID string) {
	// Kernel version pra ebpf — tracer.Run() valida >= 4.16. Lê via uname
	// e propaga pro pkg common (ebpf consome via common.GetKernelVersion).
	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err != nil {
		log.Warn("ebpf: uname failed, tracer disabled", "err", err)
		return
	}
	kv := utsToString(utsname.Release[:])
	if err := common.SetKernelVersion(kv); err != nil {
		log.Warn("ebpf: SetKernelVersion failed, tracer disabled", "kv", kv, "err", err)
		return
	}
	log.Info("ebpf: kernel detected", "version", kv)

	hostNs, err := netns.Get()
	if err != nil {
		log.Warn("ebpf: netns.Get failed, tracer disabled", "err", err)
		return
	}
	tracer := ebpf.NewTracer(hostNs, hostNs, false)
	events := make(chan ebpf.Event, 1000)

	// Hostname do nó (bare-metal): preenchido no span quando o PodResolver
	// não resolve nenhuma das pontas, permitindo o backend cruzar com
	// noc_host.hostname e materializar noc_application.
	fallback := getenvOr("ISPWATCH_HOSTNAME_OVERRIDE", "")
	if fallback == "" {
		if hn, err := os.Hostname(); err == nil {
			fallback = hn
		}
	}

	cfg := ebpf.BridgeConfig{
		ServiceName:      getenvOr("ISPWATCH_EBPF_SERVICE_NAME", "ebpf-tracer"),
		FallbackHostname: fallback,
		Log:              log,
	}

	// Tenta hookup do PodResolver via kubelet local. Sem ele, spans saem
	// sem identidade de pod (mas ainda fluem — backend trata isso).
	kubeletURL := getenvOr("ISPWATCH_KUBELET_URL", "https://localhost:10250")
	tokenFile := getenvOr("ISPWATCH_KUBELET_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	caFile := getenvOr("ISPWATCH_KUBELET_CA_FILE", "")
	insecure := getenvOr("ISPWATCH_KUBELET_INSECURE", "1") == "1"
	if resolver, err := ebpf.NewPodResolver(kubeletURL, tokenFile, caFile, insecure, log); err != nil {
		log.Warn("ebpf: pod resolver disabled (spans will lack namespace/pod)", "err", err)
	} else {
		go resolver.Run(ctx)
		cfg.PodResolver = resolver
	}

	// ContainerResolver via Docker socket — pra hosts bare-metal com containers,
	// cada container vira um service.name distinto (postgres/redis/api) em vez
	// de todos serem agregados sob o hostname. Off por default (precisa de
	// acesso ao docker.sock). Habilita via ISPWATCH_EBPF_DOCKER_RESOLVE=1.
	if getenvOr("ISPWATCH_EBPF_DOCKER_RESOLVE", "0") == "1" {
		if cr, err := ebpf.NewDockerContainerResolver(); err != nil {
			log.Warn("ebpf: docker container resolver disabled", "err", err)
		} else {
			cfg.ContainerResolver = cr
			log.Info("ebpf: docker container resolver enabled — spans get image-derived service.name")
		}
	}

	// ORDEM IMPORTA: o consumidor (RunBridge) precisa estar drenando o canal
	// ANTES de tracer.Run(), porque o step "init" do Run() despeja 1 evento por
	// PID/fd/conexão no canal. Num nó k8s isso passa de 1000 (o buffer) → o init
	// trava no envio e o Run() nunca retorna (era o "trava no step 3/4"). Com o
	// bridge já consumindo, os eventos escoam e o Run() completa o attach.
	go ebpf.RunBridge(ctx, events, sink, cfg)

	if err := tracer.Run(events); err != nil {
		log.Warn("ebpf: tracer.Run failed, tracer disabled", "err", err)
		return
	}
	log.Info("ebpf tracer started")

	go func() {
		<-ctx.Done()
		tracer.Close()
	}()

	// Self-metric publisher: every 30s, snapshot tracer.LostSamples() and
	// publish agent_ebpf_lost_samples{map=...} via __self__=true so
	// VmRemoteWriter renames it to agent_host_metric_ebpf_lost_samples and
	// labels by collector_id. Cumulative counter — operators apply rate()
	// in dashboards to spot ring-buffer undersizing.
	go publishEbpfSelfMetrics(ctx, log, tracer, metricsOut, collectorID)
}

// publishEbpfSelfMetrics drains tracer.LostSamples() periodically and
// pushes one metric per (map_name) into the shared metrics channel.
// Always tagged __self__=true so the backend's VmRemoteWriter rewrites
// the name and label per the self-metrics contract. Best-effort: if the
// channel is full we drop the snapshot (the next tick will re-emit
// cumulative values, no data lost beyond visual gap).
func publishEbpfSelfMetrics(ctx context.Context, log *slog.Logger, tr *ebpf.Tracer, out chan<- []*collectorv1.Metric, collectorID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	emit := func() {
		samples := tr.LostSamples()
		if len(samples) == 0 {
			return
		}
		now := timestamppb.Now()
		metrics := make([]*collectorv1.Metric, 0, len(samples))
		for mapName, n := range samples {
			metrics = append(metrics, &collectorv1.Metric{
				Time:       now,
				HostId:     "self",
				MetricName: "ebpf_lost_samples",
				Value:      float64(n),
				Source:     "agent.self.ebpf",
				Tags: map[string]string{
					"__self__": "true",
					"map":      mapName,
				},
			})
		}
		select {
		case out <- metrics:
		case <-ctx.Done():
		default:
			log.Warn("ebpf self-metrics channel full, dropping snapshot", "count", len(metrics))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit()
		}
	}
}

// publishOtlpHTTPSelfMetrics — análogo do publishEbpfSelfMetrics pro receiver
// OTLP/HTTP. Emite cumulative counters a cada 30s:
//
//   - agent_otlp_http_requests_total{endpoint=<path>, status=<2xx|4xx|5xx>}
//   - agent_otlp_http_spans_total
//
// VmRemoteWriter renomeia pra agent_host_metric_otlp_http_* + relabela
// collector_id. Dashboards aplicam rate(). Channel-full = drop silencioso;
// cumulative cobre a "lacuna visual" no próximo tick.
func publishOtlpHTTPSelfMetrics(ctx context.Context, log *slog.Logger, rec *otlp.HTTPReceiver, out chan<- []*collectorv1.Metric, collectorID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	emit := func() {
		stats := rec.Stats()
		// Sem nenhum hit ainda — não polua o TSDB com zeros constantes;
		// nada chega → operador não vê série fantasma antes do primeiro
		// cliente OTLP/HTTP conectar.
		if stats.RequestsTotal == 0 && stats.SpansAccepted == 0 {
			return
		}
		now := timestamppb.Now()
		metrics := make([]*collectorv1.Metric, 0, 4+len(stats.PerEndpoint))

		// Agregado total de spans aceitos via HTTP.
		metrics = append(metrics, &collectorv1.Metric{
			Time:       now,
			HostId:     "self",
			MetricName: "otlp_http_spans_total",
			Value:      float64(stats.SpansAccepted),
			Source:     "agent.self.otlp_http",
			Tags:       map[string]string{"__self__": "true"},
		})

		// Por endpoint × status. PerEndpoint key é "endpoint:bucket".
		for key, n := range stats.PerEndpoint {
			endpoint, bucket := key, ""
			if i := indexByte(key, ':'); i >= 0 {
				endpoint, bucket = key[:i], key[i+1:]
			}
			metrics = append(metrics, &collectorv1.Metric{
				Time:       now,
				HostId:     "self",
				MetricName: "otlp_http_requests_total",
				Value:      float64(n),
				Source:     "agent.self.otlp_http",
				Tags: map[string]string{
					"__self__": "true",
					"endpoint": endpoint,
					"status":   bucket,
				},
			})
		}
		select {
		case out <- metrics:
		case <-ctx.Done():
		default:
			log.Warn("otlp http self-metrics channel full, dropping snapshot", "count", len(metrics))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit()
		}
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// utsToString converte Utsname.Release ([65]int8) em string, parando no
// primeiro NUL. Sem isso o common.SetKernelVersion vê lixo no buffer e
// rejeita "0.0.0 \x00\x00...".
func utsToString(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// startJournaldLogs constrói o reader + exporter de logs do journald e
// pluga eles. Roda 2 goroutines:
//
//   - reader: subprocess journalctl + scan stdout. Emite JournaldRecord
//     pelo channel interno.
//   - exporter: drena o channel, converte cada record em LogRecord
//     OTLP, agrupa em batches e POSTa pro backend.
//
// Mais 1 goroutine pra emit self-metrics (agent_logs_*_total).
func startJournaldLogs(
	ctx context.Context,
	log *slog.Logger,
	httpEndpoint string,
	cfg *config.Config,
	out chan<- []*collectorv1.Metric,
) {
	reader := checks.NewJournaldReader(log)
	exporter, err := otlp.NewLogsExporter(
		httpEndpoint, cfg.TenantID, cfg.CollectorID,
		cfg.ClientCert, cfg.ClientKey, cfg.TrustBundle, log)
	if err != nil {
		log.Warn("logs exporter init failed (journald disabled)", "err", err)
		return
	}

	log.Info("journald logs pipeline enabled", "endpoint", httpEndpoint)
	go reader.Run(ctx)
	go exporter.Run(ctx)

	// Bridge: reader → exporter. Mantém goroutine própria pra não bloquear
	// reader se exporter estiver atrasado (LogsExporter.Push é não-bloqueante).
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rec, ok := <-reader.Out():
				if !ok {
					return
				}
				exporter.Push(otlp.LogRecord{
					TimestampUnixNano: rec.TimestampUnixNano,
					ServiceName:       rec.Unit,
					Hostname:          rec.Hostname,
					SeverityNumber:    checks.PriorityToSeverityNumber(rec.Priority),
					SeverityText:      checks.PriorityToSeverityText(rec.Priority),
					Body:              rec.Body,
					Attributes:        rec.Extras,
				})
			}
		}
	}()

	// Self-metrics publisher — 30s tick, mesmo contrato dos demais
	// (publishOtlpHTTPSelfMetrics). Counters cumulativos; dashboard rate().
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rs := reader.Stats()
				es := exporter.Stats()
				if rs.LinesTotal == 0 && es.LinesTotal == 0 {
					continue
				}
				now := timestamppb.Now()
				ms := []*collectorv1.Metric{
					{
						Time: now, HostId: "self", MetricName: "logs_lines_total",
						Value: float64(rs.LinesTotal), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true", "source": "journald"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_bytes_total",
						Value: float64(rs.BytesTotal), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true", "source": "journald"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_dropped_total",
						Value:  float64(rs.DroppedTotal + es.DroppedTotal),
						Source: "agent.self.logs",
						Tags:   map[string]string{"__self__": "true", "reason": "ratelimit_or_overflow"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_send_failures_total",
						Value: float64(es.SendFailures), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true"},
					},
				}
				select {
				case out <- ms:
				default:
					// metric channel cheio — dropa silencioso, próximo tick recupera.
				}
			}
		}
	}()
}

// startDockerLogs constrói o DockerLogsTailer + exporter e roda o pipeline.
// Pattern simétrico ao startJournaldLogs.
func startDockerLogs(
	ctx context.Context,
	log *slog.Logger,
	httpEndpoint string,
	cfg *config.Config,
	out chan<- []*collectorv1.Metric,
) {
	exporter, err := otlp.NewLogsExporter(
		httpEndpoint, cfg.TenantID, cfg.CollectorID,
		cfg.ClientCert, cfg.ClientKey, cfg.TrustBundle, log)
	if err != nil {
		log.Warn("logs exporter init failed (docker logs disabled)", "err", err)
		return
	}

	cursorPath := getenvOr("ISPWATCH_DOCKER_LOGS_CURSOR_PATH", logs.DefaultCursorPath)

	tailer, err := logs.NewDockerLogsTailer(exporter, cursorPath, log)
	if err != nil {
		log.Warn("docker logs tailer init failed (docker not available?)", "err", err)
		return
	}

	log.Info("docker logs pipeline enabled", "endpoint", httpEndpoint)
	go exporter.Run(ctx)
	go tailer.Run(ctx)

	// Self-metrics publisher — 30s tick, same pattern as journald.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ts := tailer.Stats()
				es := exporter.Stats()
				if ts.LinesTotal == 0 && es.LinesTotal == 0 {
					continue
				}
				now := timestamppb.Now()
				ms := []*collectorv1.Metric{
					{
						Time: now, HostId: "self", MetricName: "logs_lines_total",
						Value: float64(ts.LinesTotal), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true", "source": "docker"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_bytes_total",
						Value: float64(es.BytesTotal), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true", "source": "docker"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_dropped_total",
						Value:  float64(ts.DroppedTotal + es.DroppedTotal),
						Source: "agent.self.logs",
						Tags:   map[string]string{"__self__": "true", "source": "docker", "reason": "ratelimit_or_overflow"},
					},
					{
						Time: now, HostId: "self", MetricName: "logs_send_failures_total",
						Value: float64(es.SendFailures), Source: "agent.self.logs",
						Tags: map[string]string{"__self__": "true", "source": "docker"},
					},
				}
				select {
				case out <- ms:
				default:
				}
			}
		}
	}()
}
