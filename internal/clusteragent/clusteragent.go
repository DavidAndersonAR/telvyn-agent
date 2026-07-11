// Package clusteragent implementa o modo ISPWATCH_AGENT_KIND=k8s.cluster: uma
// réplica que fala com o API server do Kubernetes (in-cluster), faz LIST dos
// Events do cluster inteiro e os empurra pelo ingest certless (noc_k8s_event).
//
// É o "Cluster Agent" do plano — a peça que o node-agent (DaemonSet, só vê o
// kubelet local) não consegue entregar: visão cross-node dos eventos do cluster
// (OOMKilled, BackOff, FailedScheduling, Unhealthy…). Enxuto por design:
//
//   - D1: raw-HTTP contra https://kubernetes.default.svc (zero client-go), o
//     mesmo padrão SA-token/TLS do kubelet lister (internal/ebpf/podresolver.go).
//   - D2: pod→workload via k8smeta.WorkloadOf (strip-de-hash, O(1), sem lookup).
//   - Transporte: IngestExporter.PostK8sEvents (OTLP+Bearer iwI_), nada de gRPC.
//
// v1 = LIST periódico (não watch): o backend deduplica por evento lógico e
// agrega o count nativo do k8s, então re-enviar o mesmo evento a cada ciclo é
// idempotente (espelha count/lastTimestamp). watch+relist fica pra F1/robustez.
package clusteragent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ispwatch/collector/internal/k8smeta"
)

// EventPusher é o subset do IngestExporter usado aqui (facilita fake em teste).
type EventPusher interface {
	PostK8sEvents(ctx context.Context, payload map[string]any) error
}

// Config do cluster-agent. APIServerURL vazio desativa (sem in-cluster config).
type Config struct {
	APIServerURL  string        // https://host:port do API server
	TokenFile     string        // SA token (relido a cada request — tokens projetados rotacionam)
	CAFile        string        // CA do SA (lido 1x)
	Insecure      bool          // pula verificação TLS (dev/kind)
	Cluster       string        // nome do cluster (carimbado no payload)
	Interval      time.Duration // período do LIST (default 30s)
	IncludeNormal bool          // manda também eventos type=Normal (default só Warning)
	EventLimit    int           // ?limit= do LIST (default 1000)
}

// Agent faz o loop de coleta+push dos eventos do cluster.
type Agent struct {
	cfg       Config
	tokenFile string
	client    *http.Client
	pusher    EventPusher
	log       *slog.Logger
}

const (
	defaultInterval   = 30 * time.Second
	defaultEventLimit = 1000
)

// New monta o cliente TLS contra o API server. Erro só em CA ilegível.
func New(cfg Config, pusher EventPusher, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.APIServerURL == "" {
		return nil, fmt.Errorf("clusteragent: APIServerURL vazio (sem in-cluster config)")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.EventLimit <= 0 {
		cfg.EventLimit = defaultEventLimit
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.Insecure}
	if cfg.CAFile != "" && !cfg.Insecure {
		ca, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("clusteragent: read ca %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("clusteragent: ca %s sem PEM", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}

	return &Agent{
		cfg:       cfg,
		tokenFile: cfg.TokenFile,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		pusher: pusher,
		log:    log.With("component", "cluster-agent"),
	}, nil
}

// Run dispara o loop de LIST no intervalo configurado. Bloqueia até ctx cancelar.
func (a *Agent) Run(ctx context.Context) {
	a.log.Info("cluster-agent iniciando", "api", a.cfg.APIServerURL,
		"interval", a.cfg.Interval, "cluster", a.cfg.Cluster, "include_normal", a.cfg.IncludeNormal)
	a.tick(ctx)
	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.tick(ctx)
		}
	}
}

func (a *Agent) tick(ctx context.Context) {
	events, err := a.listEvents(ctx)
	if err != nil {
		a.log.Warn("LIST events falhou", "err", err)
		return
	}
	payload := a.buildPayload(events)
	n := len(payload["events"].([]map[string]any))
	if n == 0 {
		a.log.Debug("nenhum evento relevante no ciclo")
		return
	}
	if err := a.pusher.PostK8sEvents(ctx, payload); err != nil {
		a.log.Warn("push de eventos falhou", "err", err, "count", n)
		return
	}
	a.log.Info("eventos do cluster enviados", "count", n)
}

// listEvents faz GET /api/v1/events?limit=N no API server, paginando via
// continue token (cap defensivo de páginas pra não varrer um cluster gigante
// num v1 sem watch).
func (a *Agent) listEvents(ctx context.Context) ([]coreEvent, error) {
	token := a.readToken()
	base := strings.TrimRight(a.cfg.APIServerURL, "/") + "/api/v1/events"
	var all []coreEvent
	cont := ""
	for page := 0; page < 10; page++ {
		url := fmt.Sprintf("%s?limit=%d", base, a.cfg.EventLimit)
		if cont != "" {
			url += "&continue=" + cont
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			return all, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return all, fmt.Errorf("API server /events status %d: %s", resp.StatusCode, snippet(body))
		}
		var list coreEventList
		if err := json.Unmarshal(body, &list); err != nil {
			return all, fmt.Errorf("decode events: %w", err)
		}
		all = append(all, list.Items...)
		cont = list.Metadata.Continue
		if cont == "" {
			break
		}
		if page == 9 {
			a.log.Warn("LIST events truncado (>10 páginas) — cluster muito grande pro v1 sem watch",
				"coletados", len(all))
		}
	}
	return all, nil
}

// buildPayload mapeia os eventos crus → shape do endpoint, filtra por
// severidade (só Warning por default) e deduplica pela MESMA chave do backend
// (cluster,ns,pod,reason,involved_name) — mantendo o maior count / mais recente.
// A dedup local evita colisão de ON CONFLICT no mesmo lote e encolhe o payload.
func (a *Agent) buildPayload(events []coreEvent) map[string]any {
	dedup := make(map[string]map[string]any, len(events))
	for _, e := range events {
		if e.Reason == "" {
			continue
		}
		// Filtro de volume: por default só Warning (timeline enxuta). MAS deixa
		// passar também os motivos que o backend classifica como critical mesmo
		// sendo type=Normal (ex.: NodeNotReady, que o node-controller emite como
		// Normal) — senão um nó caindo sumiria da timeline. IncludeNormal manda tudo.
		if !a.cfg.IncludeNormal && !strings.EqualFold(e.Type, "Warning") && !criticalReason(e.Reason) {
			continue
		}
		ns := firstNonEmpty(e.InvolvedObject.Namespace, e.Metadata.Namespace)
		kind := e.InvolvedObject.Kind
		name := e.InvolvedObject.Name
		pod, workload := "", ""
		switch kind {
		case "Pod":
			pod = name
			workload = k8smeta.WorkloadOf(name)
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			workload = name
		case "ReplicaSet":
			// RS name = "app-<rsHash>"; sufixo fake pra WorkloadOf tirar o hash.
			workload = k8smeta.WorkloadOf(name + "-00000")
		}
		count := e.Count
		if e.Series != nil && e.Series.Count > count {
			count = e.Series.Count
		}
		if count < 1 {
			count = 1
		}
		occurredAt := firstNonEmpty(e.LastTimestamp, seriesTime(e), e.EventTime, e.Metadata.CreationTimestamp)

		ev := map[string]any{
			"namespace":     ns,
			"workload":      workload,
			"pod":           pod,
			"involved_kind": kind,
			"involved_name": name,
			"reason":        e.Reason,
			"event_type":    firstNonEmpty(e.Type, "Normal"),
			"message":       e.Message,
			"count":         count,
			"occurred_at":   occurredAt,
		}
		key := a.cfg.Cluster + "\x00" + ns + "\x00" + pod + "\x00" + e.Reason + "\x00" + name
		if prev, ok := dedup[key]; ok {
			// Mesma chave no lote: fica com o maior count.
			if pc, _ := prev["count"].(int); count >= pc {
				dedup[key] = ev
			}
			continue
		}
		dedup[key] = ev
	}
	out := make([]map[string]any, 0, len(dedup))
	for _, ev := range dedup {
		out = append(out, ev)
	}
	return map[string]any{"cluster": a.cfg.Cluster, "events": out}
}

func (a *Agent) readToken() string {
	if a.tokenFile == "" {
		return ""
	}
	b, err := os.ReadFile(a.tokenFile)
	if err != nil {
		a.log.Warn("read SA token falhou", "file", a.tokenFile, "err", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

func seriesTime(e coreEvent) string {
	if e.Series != nil {
		return e.Series.LastObservedTime
	}
	return ""
}

// criticalReasons espelha os motivos que o backend (k8sSeverity) trata como
// critical independentemente do type do k8s. Mantém o filtro do agente um
// SUPERSET do que o backend considera não-info, pra nunca descartar um crítico.
var criticalReasons = map[string]struct{}{
	"OOMKilling": {}, "OOMKilled": {}, "Evicted": {}, "Failed": {},
	"FailedScheduling": {}, "NodeNotReady": {}, "FailedCreatePodSandBox": {},
	"BackOff": {}, "CrashLoopBackOff": {},
}

func criticalReason(reason string) bool {
	_, ok := criticalReasons[reason]
	return ok
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func snippet(b []byte) string {
	const max = 300
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max]
	}
	return s
}

// ---- shapes do core/v1 Event (subset) ----

type coreEvent struct {
	Metadata struct {
		Namespace         string `json:"namespace"`
		Name              string `json:"name"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"involvedObject"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Type           string `json:"type"`
	Count          int    `json:"count"`
	FirstTimestamp string `json:"firstTimestamp"`
	LastTimestamp  string `json:"lastTimestamp"`
	EventTime      string `json:"eventTime"`
	Series         *struct {
		Count            int    `json:"count"`
		LastObservedTime string `json:"lastObservedTime"`
	} `json:"series"`
}

type coreEventList struct {
	Items    []coreEvent `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}
