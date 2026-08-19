// Command collector is the Telvyn on-prem agent. It ships telemetry to the
// central gateway over HTTP/OTLP with a Bearer ingest token (certless), plus
// an optional mutating-webhook mode for k8s auto-injection.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ispwatch/collector/internal/apm/concentrator"
	"github.com/ispwatch/collector/internal/apm/obfuscate"
	"github.com/ispwatch/collector/internal/apm/sampler"
	"github.com/ispwatch/collector/internal/apm/statsfwd"
	"github.com/ispwatch/collector/internal/checks"
	"github.com/ispwatch/collector/internal/clusteragent"
	"github.com/ispwatch/collector/internal/configpull"
	"github.com/ispwatch/collector/internal/ebpf"
	"github.com/ispwatch/collector/internal/ebpf/common"
	"github.com/ispwatch/collector/internal/jobpull"
	"github.com/ispwatch/collector/internal/langdetect"
	"github.com/ispwatch/collector/internal/logs"
	"github.com/ispwatch/collector/internal/otlp"
	"github.com/ispwatch/collector/internal/quarkus"
	"github.com/ispwatch/collector/internal/sbom"
	"github.com/ispwatch/collector/internal/selfmetrics"
	"github.com/ispwatch/collector/internal/webhook"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/vishvananda/netns"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Version is set at build time via -ldflags. Defaults to "dev" for local runs.
var Version = "dev"

func main() {
	// Intercept --version / -version / -v (and --webhook) early. Keeps
	// `ispwatch-agent --version` working in tarball smoke tests and ops sanity
	// checks (Plan 03-09 release pipeline).
	webhookOnly := false
	for _, a := range os.Args[1:] {
		switch a {
		case "--version", "-version", "-v":
			fmt.Printf("ispwatch-agent %s\n", Version)
			os.Exit(0)
		case "--webhook", "-webhook":
			webhookOnly = true
		}
	}

	if webhookOnly {
		// Modo Mutating Webhook server. Lê config de env vars — roda como
		// Deployment separado (não DaemonSet), com identidade TLS própria.
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

	// Modo ingest certless: manda telemetria OTLP pro gateway
	// /api/ingest/v1 com Bearer token, sem enrollment/mTLS/cert por agent. É o
	// ÚNICO modo de operação — exige ISPWATCH_INGEST_URL (+ ISPWATCH_INGEST_TOKEN).
	ingestURL := strings.TrimSpace(os.Getenv("ISPWATCH_INGEST_URL"))
	if ingestURL == "" {
		fmt.Fprintln(os.Stderr, "ISPWATCH_INGEST_URL is required (certless ingest mode)")
		os.Exit(1)
	}
	runIngestMode(ingestURL)
}

// runIngestMode roda o agent no modelo certless por token: recebe OTLP de
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
		// "eBPF / sem instrumentação". Posto depois do
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

	exporter := otlp.NewIngestExporter(ingestURL, token, hostID, cluster, Version, log)

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

			// CPU/mem/load do NÓ via /host/proc → cpu%/mem% na tela Servidores.
			// O kubelet só dá uso (cores/bytes); o /proc do host dá a % real,
			// Reporta sob o host_id do nó (não é __self__).
			checks.StartNodeSystem(ctx, log, out, nodeHostID, "/host/proc", 30*time.Second)

			// Vulnerabilidade de aplicação (camada 2/3, toggle): Trivy gera o SBOM
			// das imagens rodando no nó e o agente manda só a lista pro gateway.
			if getenvOr("ISPWATCH_SBOM_SCAN", "0") == "1" {
				startSbomScan(ctx, log, exporter, nodeHostID)
			} else {
				log.Debug("sbom scan desativado (set ISPWATCH_SBOM_SCAN=1 pra habilitar)")
			}
		}
	}

	// Docker: registra a MÁQUINA (→ noc_app_host install_mode=docker + check
	// docker.host, aparece em "Aplicações" igual o nó k8s) e roda o check
	// docker.host LOCAL (containers via /var/run/docker.sock) com o host_id
	// retornado. O collector deste agente é registrado ANTES pra amarrar
	// máquina↔collector (self-metrics dela) — e o UUID passa a viajar no
	// header X-Ispwatch-Collector de todo POST.
	// Princípio (David): a máquina é inventário/contexto de infra; a
	// APLICAÇÃO segue identificada pelo serviço (uuid), nunca pela máquina.
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "docker") {
		collectorID := ""
		if cid, _, err := exporter.RegisterCollector(ctx, hostID, []string{"metrics", "checks"}, "docker"); err != nil {
			log.Warn("docker: registro de collector falhou — sigo sem vínculo máquina↔collector", "err", err)
		} else {
			collectorID = cid
			exporter.SetCollectorID(cid)
		}
		dockerHostID, err := exporter.RegisterDockerHost(ctx, hostID, collectorID)
		if err != nil {
			log.Warn("docker register falhou — sigo só com métricas de host", "err", err)
		} else {
			log.Info("máquina docker registrada", "host_id", dockerHostID, "hostname", hostID)
			startDockerCheck(ctx, log, out, dockerHostID)
		}
	}

	// Linux puro (systemd): registra a MÁQUINA (→ noc_app_host install_mode=linux
	// + check linux.system, aparece em "Aplicações" igual o nó k8s / a máquina
	// docker) e roda o check linux.system LOCAL (CPU/mem/disco/rede da máquina)
	// com o host_id retornado. Espelho exato do ramo docker acima — a máquina é
	// inventário/contexto de infra; a APLICAÇÃO segue identificada pelo serviço
	// (uuid), nunca pela máquina.
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "linux") {
		collectorID := ""
		if cid, _, err := exporter.RegisterCollector(ctx, hostID, []string{"metrics", "checks"}, "linux"); err != nil {
			log.Warn("linux: registro de collector falhou — sigo sem vínculo máquina↔collector", "err", err)
		} else {
			collectorID = cid
			exporter.SetCollectorID(cid)
		}
		linuxHostID, err := exporter.RegisterLinuxHost(ctx, hostID, collectorID)
		if err != nil {
			log.Warn("linux register falhou — sigo só com métricas de host", "err", err)
		} else {
			log.Info("máquina linux registrada", "host_id", linuxHostID, "hostname", hostID)
			startLinuxSystemCheck(ctx, log, out, linuxHostID)
			// Descoberta de serviços locais (processos que escutam porta +
			// CPU/mem) → a lente de Máquina mostra "o que roda aqui". Toggle
			// ISPWATCH_HOST_SERVICES (ligado por padrão).
			if hostServicesEnabled() {
				startHostServicesReport(ctx, log, exporter, linuxHostID)
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
				KubeState:     getenvOr("ISPWATCH_CLUSTER_KUBESTATE", "1") != "0",
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
	// junto com k8sattributes do OTel): spans de apps auto-instrumentadas
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

			// Detecção de linguagem por processo: olha /proc,
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

	// Trace-agent: resume os spans NA BORDA. O corpo cru segue
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
	// Sampler: guarda todo erro + todo trace lento (>2s) +
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

	// Coleta opcional de logs: taila /var/log/pods (CRI) e
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
		startIngestChecks(ctx, log, exporter, apmStats, token, ingestURL, hostID, out)
	} else {
		log.Debug("checagens agendadas desativadas (set ISPWATCH_CHECKS_ENABLED=1 pra habilitar)")
	}

	// Receiver OTLP/HTTP: bind NÃO-FATAL. Se a porta está
	// ocupada (outro processo no host), o agente loga e SEGUE — métricas, logs,
	// checks e o node-system continuam. Um receptor opcional não derruba o
	// processo. Desliga de propósito com ISPWATCH_OTLP_HTTP_DISABLE=1; muda de
	// porta com ISPWATCH_OTLP_HTTP_PORT.
	if getenvOr("ISPWATCH_OTLP_HTTP_DISABLE", "0") == "1" {
		log.Info("otlp http receiver desligado via ISPWATCH_OTLP_HTTP_DISABLE")
	} else {
		go func() {
			if err := rec.Start(ctx); err != nil {
				log.Warn("otlp http receiver não subiu — sigo sem ele (porta ocupada?)",
					"err", err, "addr", httpAddr)
			}
		}()
	}
	<-ctx.Done()
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

	// Service tagging unificado: o service do log vem das labels do pod
	// (lidas do kubelet /pods), para coincidir com o
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
		log.Info("logs: service tagging unificado ativo")
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
func startIngestChecks(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter, apmStats *statsfwd.Forwarder, token, ingestURL, hostID string, out chan<- []*collectorv1.Metric) {
	name := strings.TrimSpace(hostID)
	if name == "" {
		name, _ = os.Hostname()
	}
	// Base raiz do servidor (config-pull fica em /api/collector/v1/config, fora
	// do /api/ingest/v1).
	base := strings.TrimRight(strings.TrimSpace(ingestURL), "/")
	base = strings.TrimRight(strings.TrimSuffix(base, "/api/ingest/v1"), "/")

	runtime := checks.New(ctx, log, checks.Default, out)
	checks.SetDeviceMetadataPusher(exporter)
	checks.SetDeviceConfigPusher(exporter) // NCM: check device.config_backup manda a running-config coletada
	runtime.SetWorkerPools(5, 10)
	runtime.SetJitter(1000)
	runtime.SetTagger(checks.NewTagger(10000, log)) // era config.DefaultTaggerBudget
	// Motivo da falha vai pro backend, não só pro log daqui: sem isto a tela do
	// equipamento mostra "warning" e o operador precisa de SSH nesta máquina.
	// Só dispara na MUDANÇA de estado, então é barato.
	runtime.SetStatusReporter(func(checkID string, ok bool, message string) {
		go func() {
			postCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := exporter.PostCheckStatus(postCtx, checkID, ok, message); err != nil {
				log.Debug("check status não reportado", "check_id", checkID, "err", err)
			}
		}()
	})

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

	// F2b — só o Linux systemd tem o helper root de upgrade. Nos outros modos
	// (k8s/docker) o marcador fica vazio → o agente ignora should_update (k8s/docker
	// atualizam via helm/docker, decisão F3). Path override via env pra testes.
	updateMarker := ""
	if strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "linux") {
		updateMarker = getenvOr("ISPWATCH_UPDATE_MARKER_PATH", "/var/lib/ispwatch/update-requested")
	}

	go runCollectorRegistrationLoop(ctx, log, 2*time.Second, 60*time.Second,
		func(ctx context.Context) (string, string, error) {
			return exporter.RegisterCollector(ctx, name, collectorCapabilities(), collectorInstallMode())
		}, func(collectorID, tenantID string) {
			exporter.SetCollectorID(collectorID)
			if envEnabled("ISPWATCH_SSH") {
				go func() {
					if err := jobpull.Run(ctx, jobpull.Config{
						Endpoint: base, CollectorID: collectorID, TenantID: tenantID,
						PollInterval: 5 * time.Second, HTTPClient: bearerClient, Logger: log,
					}); err != nil {
						log.Warn("device job pull encerrou", "err", err)
					}
				}()
			}
			go func() {
				if err := configpull.Run(ctx, configpull.Config{
					Endpoint:         base,
					CollectorID:      collectorID,
					TenantID:         tenantID,
					PollInterval:     time.Duration(pollSecs) * time.Second,
					HTTPClient:       bearerClient,
					Logger:           log,
					UpdateMarkerPath: updateMarker,
					PolicyChanged: func(modules []string) {
						exporter.SetEnabledModules(modules)
						apmEnabled := false
						for _, module := range modules {
							if module == "APM" {
								apmEnabled = true
								break
							}
						}
						apmStats.SetEnabled(apmEnabled)
					},
				}, runtime); err != nil {
					log.Warn("config pull (ingest) encerrou", "err", err)
				}
			}()
			log.Info("checagens agendadas habilitadas (config-pull)",
				"collector_id", collectorID, "tenant", tenantID, "base", base, "poll_s", pollSecs)
		})
}

// collectorCapabilities anuncia o que esta instalacao realmente pode executar.
// metrics/checks formam o contrato base; protocolos de rede só entram quando o
// operador os ativou no comando gerado pelo portal.
func collectorCapabilities() []string {
	caps := []string{"metrics", "checks"}
	if !strings.EqualFold(getenvOr("ISPWATCH_AGENT_KIND", ""), "snmp") {
		return caps
	}
	for _, item := range []struct {
		env string
		cap string
	}{
		{"ISPWATCH_SNMP", "snmp"},
		{"ISPWATCH_ICMP", "icmp"},
		{"ISPWATCH_LLDP", "lldp"},
		{"ISPWATCH_SSH", "ssh"},
	} {
		if envEnabled(item.env) {
			caps = append(caps, item.cap)
			if item.env == "ISPWATCH_SSH" {
				caps = append(caps, "ssh_readonly_v1")
			}
		}
	}
	return caps
}

func collectorInstallMode() string {
	if mode := strings.ToLower(strings.TrimSpace(getenvOr("ISPWATCH_INSTALL_MODE", ""))); mode == "docker" || mode == "linux" || mode == "k8s" {
		return mode
	}
	switch strings.ToLower(strings.TrimSpace(getenvOr("ISPWATCH_AGENT_KIND", ""))) {
	case "docker":
		return "docker"
	case "linux":
		return "linux"
	case "k8s.node", "k8s.cluster":
		return "k8s"
	default:
		return ""
	}
}

func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(getenvOr(name, "0"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// runCollectorRegistrationLoop tolera backend indisponível no boot sem bloquear
// a inicialização do agent. Só libera o config-pull após obter identidade válida;
// depois mantém o mesmo registro como heartbeat periódico.
func runCollectorRegistrationLoop(
	ctx context.Context,
	log *slog.Logger,
	initialBackoff, heartbeatInterval time.Duration,
	register func(context.Context) (string, string, error),
	onRegistered func(string, string),
) {
	backoff := initialBackoff
	for {
		collectorID, tenantID, err := register(ctx)
		if err == nil && collectorID != "" {
			onRegistered(collectorID, tenantID)
			break
		}
		if err == nil {
			err = fmt.Errorf("collector_id vazio")
		}
		log.Warn("checks: registro de collector falhou — tentando novamente", "err", err, "retry_in", backoff)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}

	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, _, err := register(ctx); err != nil {
				log.Warn("heartbeat: re-registro do collector falhou", "err", err)
			}
		}
	}
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

// startDockerCheck roda o check docker.host LOCAL no modo ingest (espelho do
// startKubeletCheck): lista/mede os containers via /var/run/docker.sock e
// emite docker.container.* com o host_id da máquina registrada. As métricas
// saem pelo mesmo canal `out` (→ PostMetrics Bearer). A factory já faz Ping
// cedo — sem socket montado, loga o hint e não sobe (best-effort).
func startDockerCheck(ctx context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, hostID string) {
	factory, ok := checks.Default.Get("docker.host")
	if !ok {
		log.Warn("docker.host check factory ausente")
		return
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "docker.host-" + hostID,
		CheckType: "docker.host",
		HostId:    hostID,
		Enabled:   true,
		Interval:  durationpb.New(60 * time.Second),
	}
	chk, err := factory(cfg)
	if err != nil {
		log.Warn("docker.host check não subiu (monte /var/run/docker.sock no container do agente)", "err", err)
		return
	}
	clog := log.With("component", "docker-host", "host_id", hostID)
	go func() {
		runOnce := func() {
			ms, err := chk.Run(ctx)
			if err != nil {
				clog.Debug("docker.host run error", "err", err)
				return
			}
			if len(ms) == 0 {
				return
			}
			select {
			case out <- ms:
			case <-ctx.Done():
			default:
				clog.Warn("docker.host out channel full, dropping", "count", len(ms))
			}
		}
		runOnce()
		t := time.NewTicker(60 * time.Second)
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
	clog.Info("docker.host check started (local)", "interval", "60s")
}

// startLinuxSystemCheck roda o check linux.system LOCAL no modo ingest (espelho
// do startDockerCheck): mede CPU/mem/disco/rede da máquina via gopsutil e emite
// as métricas com o host_id da máquina Linux registrada. Saem pelo mesmo canal
// `out` (→ PostMetrics Bearer). A 1ª amostra de CPU só firma a baseline (delta),
// então cpu.* aparece a partir do 2º tick — comportamento normal do check.
func startLinuxSystemCheck(ctx context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, hostID string) {
	factory, ok := checks.Default.Get("linux.system")
	if !ok {
		log.Warn("linux.system check factory ausente")
		return
	}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "linux.system-" + hostID,
		CheckType: "linux.system",
		HostId:    hostID,
		Enabled:   true,
		Interval:  durationpb.New(30 * time.Second),
	}
	chk, err := factory(cfg)
	if err != nil {
		log.Warn("linux.system check não subiu", "err", err)
		return
	}
	clog := log.With("component", "linux-system", "host_id", hostID)
	go func() {
		runOnce := func() {
			ms, err := chk.Run(ctx)
			if err != nil {
				clog.Debug("linux.system run error", "err", err)
				return
			}
			if len(ms) == 0 {
				return
			}
			select {
			case out <- ms:
			case <-ctx.Done():
			default:
				clog.Warn("linux.system out channel full, dropping", "count", len(ms))
			}
		}
		runOnce()
		t := time.NewTicker(30 * time.Second)
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
	clog.Info("linux.system check started (local)", "interval", "30s")
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
