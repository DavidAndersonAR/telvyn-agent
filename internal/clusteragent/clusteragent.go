// Package clusteragent implementa o modo ISPWATCH_AGENT_KIND=k8s.cluster: uma
// réplica que fala com o API server do Kubernetes (in-cluster), faz LIST dos
// recursos e Events do cluster inteiro e os empurra pelo ingest certless.
//
// É o "Cluster Agent" do plano — a peça que o node-agent (DaemonSet, só vê o
// kubelet local) não consegue entregar: visão cross-node dos eventos do cluster
// (OOMKilled, BackOff, FailedScheduling, Unhealthy…). Enxuto por design:
//
//   - D1: raw-HTTP contra https://kubernetes.default.svc (zero client-go), o
//     mesmo padrão SA-token/TLS do kubelet lister (internal/ebpf/podresolver.go).
//   - D2: pod→workload via k8smeta.WorkloadOf (strip-de-hash, O(1), sem lookup).
//   - Transporte: IngestExporter.PostK8sEvents/PostK8sInventory (JSON+Bearer), nada de gRPC.
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
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Ingest é o subset do IngestExporter usado aqui (facilita fake em teste):
// inventário, eventos (timeline) e métricas kube-state.
type Ingest interface {
	PostK8sEvents(ctx context.Context, payload map[string]any) error
	PostK8sInventory(ctx context.Context, payload map[string]any) error
	PostMetrics(ctx context.Context, metrics []*collectorv1.Metric) error
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
	KubeState     bool          // emite métricas kube-state (pods por fase + deployments)
	Inventory     bool          // envia snapshot de identidade/estado dos recursos
}

// Agent faz o loop de coleta+push do cluster (inventário + eventos + kube-state).
type Agent struct {
	cfg       Config
	tokenFile string
	client    *http.Client
	ingest    Ingest
	log       *slog.Logger
	sequence  uint64
}

const (
	defaultInterval       = 30 * time.Second
	defaultEventLimit     = 1000
	maxInventoryResources = 10_000
)

// New monta o cliente TLS contra o API server. Erro só em CA ilegível.
func New(cfg Config, ingest Ingest, log *slog.Logger) (*Agent, error) {
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
		ingest: ingest,
		log:    log.With("component", "cluster-agent"),
	}, nil
}

// Run dispara o loop de coleta no intervalo configurado. Bloqueia até ctx cancelar.
func (a *Agent) Run(ctx context.Context) {
	a.log.Info("cluster-agent iniciando", "api", a.cfg.APIServerURL,
		"interval", a.cfg.Interval, "cluster", a.cfg.Cluster,
		"include_normal", a.cfg.IncludeNormal, "kube_state", a.cfg.KubeState)
	a.collect(ctx)
	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.collect(ctx)
		}
	}
}

// collect roda um ciclo: inventário + eventos (timeline) + kube-state.
func (a *Agent) collect(ctx context.Context) {
	if a.cfg.Inventory {
		a.pushInventory(ctx)
	}
	a.pushEvents(ctx)
	if a.cfg.KubeState {
		a.pushKubeState(ctx)
	}
}

// pushInventory envia um snapshot completo de identidade/estado. O snapshot
// é separado das métricas porque nomes, namespaces e owners precisam continuar
// visíveis mesmo quando um pod está sem amostras de CPU/memória.
func (a *Agent) pushInventory(ctx context.Context) {
	a.sequence++
	resources, err := a.collectInventory(ctx)
	if err != nil {
		a.log.Warn("k8s inventory LIST falhou", "err", err)
		return
	}
	payload := map[string]any{
		"cluster":       a.cfg.Cluster,
		"snapshot":      true,
		"sync_sequence": a.sequence,
		"resources":     resources,
	}
	if err := a.ingest.PostK8sInventory(ctx, payload); err != nil {
		a.log.Warn("push de inventário falhou", "err", err, "count", len(resources))
		return
	}
	a.log.Info("inventário Kubernetes enviado", "resources", len(resources), "sequence", a.sequence)
}

type inventorySource struct {
	path string
	kind string
}

var inventorySources = []inventorySource{
	// O ClusterRole existente já concede somente leitura de Pods. Isso basta
	// para o catálogo da tela e evita aumentar o blast radius do agent.
	{path: "/api/v1/pods", kind: "Pod"},
}

type inventoryList struct {
	Items    []json.RawMessage `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

type inventoryOwner struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type inventoryObject struct {
	Metadata struct {
		Namespace       string            `json:"namespace"`
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []inventoryOwner  `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string           `json:"phase"`
		Conditions []map[string]any `json:"conditions"`
	} `json:"status"`
}

func (a *Agent) collectInventory(ctx context.Context) ([]map[string]any, error) {
	resources := make([]map[string]any, 0, 256)
	for _, source := range inventorySources {
		err := a.apiGetPaged(ctx, source.path, func(body []byte) (string, error) {
			var list inventoryList
			if err := json.Unmarshal(body, &list); err != nil {
				return "", fmt.Errorf("decode %s: %w", source.kind, err)
			}
			for _, raw := range list.Items {
				resource, err := inventoryResource(source.kind, raw)
				if err != nil {
					return "", err
				}
				resources = append(resources, resource)
				if len(resources) > maxInventoryResources {
					return "", fmt.Errorf("inventário excede %d recursos", maxInventoryResources)
				}
			}
			return list.Metadata.Continue, nil
		})
		if err != nil {
			return nil, err
		}
	}
	return resources, nil
}

func inventoryResource(kind string, raw []byte) (map[string]any, error) {
	var obj inventoryObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("decode %s resource: %w", kind, err)
	}
	if obj.Metadata.UID == "" || obj.Metadata.Name == "" {
		return nil, fmt.Errorf("%s resource without metadata.uid/name", kind)
	}
	labels := obj.Metadata.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	conditions := obj.Status.Conditions
	if conditions == nil {
		conditions = []map[string]any{}
	}
	resource := map[string]any{
		"kind":             kind,
		"uid":              obj.Metadata.UID,
		"namespace":        obj.Metadata.Namespace,
		"name":             obj.Metadata.Name,
		"node_name":        obj.Spec.NodeName,
		"phase":            obj.Status.Phase,
		"status":           obj.Status.Phase,
		"labels":           labels,
		"conditions":       conditions,
		"resource_version": obj.Metadata.ResourceVersion,
	}
	if kind == "Pod" {
		if owner := podWorkload(obj.Metadata.OwnerReferences); owner != nil {
			resource["workload_kind"] = owner.Kind
			resource["workload_name"] = owner.Name
		}
	} else if isWorkloadKind(kind) {
		resource["workload_kind"] = kind
		resource["workload_name"] = obj.Metadata.Name
	}
	return resource, nil
}

func podWorkload(owners []inventoryOwner) *inventoryOwner {
	for _, owner := range owners {
		switch owner.Kind {
		case "ReplicaSet":
			return &inventoryOwner{Kind: "Deployment", Name: k8smeta.WorkloadOf(owner.Name + "-00000")}
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			return &owner
		}
	}
	return nil
}

func isWorkloadKind(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func (a *Agent) pushEvents(ctx context.Context) {
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
	if err := a.ingest.PostK8sEvents(ctx, payload); err != nil {
		a.log.Warn("push de eventos falhou", "err", err, "count", n)
		return
	}
	a.log.Info("eventos do cluster enviados", "count", n)
}

// pushKubeState coleta contagem de pods por (namespace, fase) + réplicas de
// deployment (desired/ready/available) e empurra como métricas VM. As tags
// casam o contrato do backend: kube_cluster_name + pod_phase/kube_namespace/
// kube_deployment (tenant_id é injetado server-side pelo token). O nome usa
// prefixo k8s. → o backend renomeia namespace→kube_namespace e o ponto vira
// underscore no VM (k8s.namespace.pod_count → k8s_namespace_pod_count).
func (a *Agent) pushKubeState(ctx context.Context) {
	var metrics []*collectorv1.Metric
	if m, err := a.collectPodPhases(ctx); err != nil {
		a.log.Warn("kube-state pods falhou", "err", err)
	} else {
		metrics = append(metrics, m...)
	}
	if m, err := a.collectDeployments(ctx); err != nil {
		a.log.Warn("kube-state deployments falhou", "err", err)
	} else {
		metrics = append(metrics, m...)
	}
	if len(metrics) == 0 {
		return
	}
	if err := a.ingest.PostMetrics(ctx, metrics); err != nil {
		a.log.Warn("kube-state push falhou", "err", err, "count", len(metrics))
		return
	}
	a.log.Info("kube-state enviado", "metrics", len(metrics))
}

// collectPodPhases faz LIST cluster-wide de pods e conta por (namespace, fase)
// → uma série k8s.namespace.pod_count por combinação.
func (a *Agent) collectPodPhases(ctx context.Context) ([]*collectorv1.Metric, error) {
	counts := map[[2]string]int{} // {namespace, phase} → count
	err := a.apiGetPaged(ctx, "/api/v1/pods", func(body []byte) (string, error) {
		var list podList
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("decode pods: %w", err)
		}
		for _, p := range list.Items {
			phase := p.Status.Phase
			if phase == "" {
				phase = "Unknown"
			}
			counts[[2]string{p.Metadata.Namespace, phase}]++
		}
		return list.Metadata.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	metrics := make([]*collectorv1.Metric, 0, len(counts))
	for k, n := range counts {
		metrics = append(metrics, a.metric("k8s.namespace.pod_count", float64(n), map[string]string{
			"kube_cluster_name": a.cfg.Cluster,
			"kube_namespace":    k[0],
			"pod_phase":         k[1],
		}))
	}
	return metrics, nil
}

// collectDeployments faz LIST cluster-wide de deployments e emite as 3 séries
// de réplica por workload (desired/ready/available) — a saúde do rollout.
func (a *Agent) collectDeployments(ctx context.Context) ([]*collectorv1.Metric, error) {
	var metrics []*collectorv1.Metric
	err := a.apiGetPaged(ctx, "/apis/apps/v1/deployments", func(body []byte) (string, error) {
		var list deploymentList
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("decode deployments: %w", err)
		}
		for _, d := range list.Items {
			base := map[string]string{
				"kube_cluster_name": a.cfg.Cluster,
				"kube_namespace":    d.Metadata.Namespace,
				"kube_deployment":   d.Metadata.Name,
			}
			desired := 0
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			metrics = append(metrics,
				a.metric("k8s.deployment.replicas_desired", float64(desired), base),
				a.metric("k8s.deployment.replicas_ready", float64(d.Status.ReadyReplicas), base),
				a.metric("k8s.deployment.replicas_available", float64(d.Status.AvailableReplicas), base),
			)
		}
		return list.Metadata.Continue, nil
	})
	return metrics, err
}

// metric monta um gauge com uma CÓPIA das tags (evita compartilhar o map base
// entre séries). tenant_id/host_id ficam de fora — o backend injeta o tenant
// pelo token e a métrica é tag-based (sem host).
func (a *Agent) metric(name string, val float64, tags map[string]string) *collectorv1.Metric {
	t := make(map[string]string, len(tags))
	for k, v := range tags {
		t[k] = v
	}
	return &collectorv1.Metric{
		MetricName: name,
		Value:      val,
		Tags:       t,
		Source:     "k8s.cluster",
	}
}

// listEvents faz LIST paginado de /api/v1/events e devolve os Events crus.
func (a *Agent) listEvents(ctx context.Context) ([]coreEvent, error) {
	var all []coreEvent
	err := a.apiGetPaged(ctx, "/api/v1/events", func(body []byte) (string, error) {
		var list coreEventList
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("decode events: %w", err)
		}
		all = append(all, list.Items...)
		return list.Metadata.Continue, nil
	})
	return all, err
}

const maxListPages = 10

// apiGetPaged faz GET paginado (continue token) num recurso do API server,
// chamando decodePage por página (que devolve o próximo continue token). Cap
// defensivo de páginas pra não varrer um cluster gigante num v1 sem watch.
func (a *Agent) apiGetPaged(ctx context.Context, path string, decodePage func(body []byte) (cont string, err error)) error {
	base := strings.TrimRight(a.cfg.APIServerURL, "/") + path
	cont := ""
	for page := 0; page < maxListPages; page++ {
		url := fmt.Sprintf("%s?limit=%d", base, a.cfg.EventLimit)
		if cont != "" {
			url += "&continue=" + cont
		}
		body, err := a.apiGet(ctx, url)
		if err != nil {
			return err
		}
		cont, err = decodePage(body)
		if err != nil {
			return err
		}
		if cont == "" {
			return nil
		}
	}
	a.log.Warn("LIST truncado (>páginas) — cluster grande demais pro v1 sem watch", "path", path)
	return nil
}

// apiGet faz um GET autenticado (SA token relido) no API server e devolve o
// corpo (cap 32MB). Erro em status != 200.
func (a *Agent) apiGet(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if token := a.readToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("API server GET status %d: %s", resp.StatusCode, snippet(body))
	}
	return body, nil
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

// ---- shapes de kube-state (subset) ----

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

type deploymentList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int `json:"replicas"`
		} `json:"spec"`
		Status struct {
			Replicas          int `json:"replicas"`
			ReadyReplicas     int `json:"readyReplicas"`
			AvailableReplicas int `json:"availableReplicas"`
			UpdatedReplicas   int `json:"updatedReplicas"`
		} `json:"status"`
	} `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}
