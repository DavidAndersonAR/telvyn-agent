// podresolver.go — resolve pid → (namespace, pod) lendo /proc/PID/cgroup
// e cruzando com o kubelet local (/pods).
//
// Implementa a interface PodResolver consumida pelo bridge. Sem isso, todo
// span sai com service.name="ebpf-tracer" e namespace/pod vazios — backend
// não consegue ligar o span a um host_id pra exibir no /aplicações.
//
// Dois caches independentes:
//   1. pid → containerID, lookup via /proc/PID/cgroup. TTL longo (pids
//      reciclam mas containerID é estável enquanto o container vive).
//   2. containerID → (ns, pod), via GET kubelet /pods. Refresh em loop
//      separado (30s — kubelet enumera todos os pods do node, barato).

package ebpf

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
	"sync"
	"time"

	"github.com/ispwatch/collector/internal/ebpf/cgroup"
	"github.com/ispwatch/collector/internal/k8smeta"
)

// KubeletPodLister resolve container_id → (namespace, pod). Implementada
// pelo httpPodLister mas testes podem injetar fake.
type KubeletPodLister interface {
	List(ctx context.Context) (PodIndex, error)
}

// PodIndex é o snapshot retornado pelo kubelet: containerID→pod E podIP→pod.
// IP é a chave pra resolver "qual pod recebe esta conexão" (o lado server
// das queries DB). Cachear separado é mais barato do que iterar a lista
// inteira a cada query.
type PodIndex struct {
	ByContainerID map[string]NamespacedName
	ByPodIP       map[string]NamespacedName
	ByNsPod       map[string]PodSvcMeta // "namespace/pod" → unified service tagging
}

type NamespacedName struct {
	Namespace string
	Pod       string
	Workload  string // Deployment/StatefulSet/DaemonSet derivado (ownerRef → k8smeta.WorkloadOf)
	Node      string // spec.nodeName do pod
}

// PodSvcMeta carrega a unified service tagging lida das labels do pod
// compatíveis de service/version/env — para carimbar log/metric com o
// mesmo service dos traces. Vazio quando o pod não tem a label.
type PodSvcMeta struct {
	Service string
	Version string
	Env     string
}

// PodResolverImpl satisfaz PodResolver. Construída via NewPodResolver.
type PodResolverImpl struct {
	lister KubeletPodLister
	log    *slog.Logger

	mu         sync.RWMutex
	pidToID    map[uint32]pidCacheEntry
	idToPod    map[string]NamespacedName // containerID  → pod
	ipToPod    map[string]NamespacedName // pod IP       → pod (lado server)
	nsPodToSvc map[string]PodSvcMeta     // "namespace/pod" → unified service tagging

	listInterval time.Duration
}

type pidCacheEntry struct {
	containerID string
	expires     time.Time
}

const (
	pidCacheTTL  = 5 * time.Minute
	listInterval = 30 * time.Second
)

// NewPodResolver — kubeletURL formato "https://localhost:10250", tokenFile
// e caFile do serviceaccount montado no pod. Quando vazios, usa
// InsecureSkipVerify (válido pra k3d/dev).
func NewPodResolver(kubeletURL, tokenFile, caFile string, insecure bool, log *slog.Logger) (*PodResolverImpl, error) {
	if log == nil {
		log = slog.Default()
	}
	lister, err := newHTTPPodLister(kubeletURL, tokenFile, caFile, insecure)
	if err != nil {
		return nil, fmt.Errorf("kubelet pod lister: %w", err)
	}
	return &PodResolverImpl{
		lister:       lister,
		log:          log.With("component", "ebpf-pod-resolver"),
		pidToID:      map[uint32]pidCacheEntry{},
		idToPod:      map[string]NamespacedName{},
		ipToPod:      map[string]NamespacedName{},
		nsPodToSvc:   map[string]PodSvcMeta{},
		listInterval: listInterval,
	}, nil
}

// Run dispara o refresh loop do kubelet. Bloqueia até ctx cancelar.
func (r *PodResolverImpl) Run(ctx context.Context) {
	r.refresh(ctx)
	ticker := time.NewTicker(r.listInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

func (r *PodResolverImpl) refresh(ctx context.Context) {
	idx, err := r.lister.List(ctx)
	if err != nil {
		r.log.Warn("kubelet /pods list failed", "err", err)
		return
	}
	r.mu.Lock()
	r.idToPod = idx.ByContainerID
	r.ipToPod = idx.ByPodIP
	r.nsPodToSvc = idx.ByNsPod
	r.mu.Unlock()
	r.log.Debug("kubelet /pods refresh",
		"containers", len(idx.ByContainerID), "ips", len(idx.ByPodIP))
}

// Resolve satisfaz a interface PodResolver do bridge — lado CLIENT (caller).
// Lê /proc/PID/cgroup no miss, cacheia, e cruza com o snapshot de pods do
// kubelet.
func (r *PodResolverImpl) Resolve(pid uint32) (string, string, bool) {
	containerID := r.containerIDFor(pid)
	if containerID == "" {
		return "", "", false
	}
	r.mu.RLock()
	pod, ok := r.idToPod[containerID]
	r.mu.RUnlock()
	if !ok {
		return "", "", false
	}
	return pod.Namespace, pod.Pod, true
}

// ResolveIP resolve um endereço IP pra (namespace, pod) — lado SERVER da
// conexão. Pra spans de DB (Postgres/Redis/MySQL/...), o pod "dono" da
// query é o servidor que recebeu o request, não o cliente que fez. Esta
// é a chave pra mostrar queries no pod do banco.
//
// O IP deve ser o pod IP real (depois do DNAT do kube-proxy). O upstream
// coroot fornece ActualDstAddr resolvido via conntrack pra esse propósito.
func (r *PodResolverImpl) ResolveIP(ip string) (string, string, bool) {
	if ip == "" {
		return "", "", false
	}
	r.mu.RLock()
	pod, ok := r.ipToPod[ip]
	r.mu.RUnlock()
	if !ok {
		return "", "", false
	}
	return pod.Namespace, pod.Pod, true
}

// ResolveIPMeta é como ResolveIP mas devolve também workload e node do pod.
// Usado pelo enricher OTLP (carimba k8s.deployment.name / k8s.node.name além de
// namespace/pod). NÃO substitui ResolveIP — o bridge eBPF usa a assinatura
// enxuta (namespace, pod, ok).
func (r *PodResolverImpl) ResolveIPMeta(ip string) (namespace, pod, workload, node string, ok bool) {
	if ip == "" {
		return "", "", "", "", false
	}
	r.mu.RLock()
	nn, found := r.ipToPod[ip]
	r.mu.RUnlock()
	if !found {
		return "", "", "", "", false
	}
	return nn.Namespace, nn.Pod, nn.Workload, nn.Node, true
}

// ServiceForPod devolve a unified service tagging (service/version/env) lida das
// labels do pod — pra carimbar os logs com o MESMO service dos traces (igual
// legadas). ok=false quando o pod não tem uma label de service;
// nesse caso o chamador cai no nome derivado do workload.
func (r *PodResolverImpl) ServiceForPod(namespace, pod string) (service, version, env string, ok bool) {
	r.mu.RLock()
	m, found := r.nsPodToSvc[namespace+"/"+pod]
	r.mu.RUnlock()
	if !found || m.Service == "" {
		return "", "", "", false
	}
	return m.Service, m.Version, m.Env, true
}

func (r *PodResolverImpl) containerIDFor(pid uint32) string {
	now := time.Now()
	r.mu.RLock()
	entry, ok := r.pidToID[pid]
	r.mu.RUnlock()
	if ok && now.Before(entry.expires) {
		return entry.containerID
	}

	cgPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	cg, err := cgroup.NewFromProcessCgroupFile(cgPath)
	if err != nil {
		// pid já morreu, ou /proc não acessível — cacheia "" pra não
		// repetir lookup por TTL curto.
		r.mu.Lock()
		r.pidToID[pid] = pidCacheEntry{containerID: "", expires: now.Add(30 * time.Second)}
		r.mu.Unlock()
		return ""
	}
	id := cg.ContainerId
	r.mu.Lock()
	r.pidToID[pid] = pidCacheEntry{containerID: id, expires: now.Add(pidCacheTTL)}
	r.mu.Unlock()
	return id
}

// httpPodLister bate em https://kubelet/pods (porta 10250) com bearer
// token do serviceaccount. Retorna mapa containerID (sem prefixo
// "containerd://") → NamespacedName.
type httpPodLister struct {
	url    string
	token  string
	client *http.Client
}

func newHTTPPodLister(url, tokenFile, caFile string, insecure bool) (*httpPodLister, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
	if caFile != "" && !insecure {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("ca %s contains no PEM", caFile)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}
	token := ""
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read token %s: %w", tokenFile, err)
		}
		token = strings.TrimSpace(string(b))
	}
	return &httpPodLister{
		url:   strings.TrimRight(url, "/") + "/pods",
		token: token,
		client: &http.Client{
			Timeout:   8 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (h *httpPodLister) List(ctx context.Context) (PodIndex, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return PodIndex{}, err
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return PodIndex{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return PodIndex{}, fmt.Errorf("kubelet /pods status %d: %s", resp.StatusCode, string(body))
	}
	var list kubeletPodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return PodIndex{}, fmt.Errorf("decode kubelet /pods: %w", err)
	}
	byID := make(map[string]NamespacedName, len(list.Items)*2)
	byIP := make(map[string]NamespacedName, len(list.Items)*2)
	byNsPod := make(map[string]PodSvcMeta, len(list.Items))
	for _, p := range list.Items {
		ns := NamespacedName{
			Namespace: p.Metadata.Namespace,
			Pod:       p.Metadata.Name,
			Workload:  deriveWorkload(p.Metadata.Name, p.Metadata.OwnerReferences),
			Node:      p.Spec.NodeName,
		}
		// Service tagging unificado: lê labels compatíveis do pod para carimbar
		// o log com o mesmo service dos traces.
		if svc := p.Metadata.Labels["tags.datadoghq.com/service"]; svc != "" {
			byNsPod[p.Metadata.Namespace+"/"+p.Metadata.Name] = PodSvcMeta{
				Service: svc,
				Version: p.Metadata.Labels["tags.datadoghq.com/version"],
				Env:     p.Metadata.Labels["tags.datadoghq.com/env"],
			}
		}
		for _, c := range p.Status.ContainerStatuses {
			id := stripContainerIDPrefix(c.ContainerID)
			if id != "" {
				byID[id] = ns
			}
		}
		for _, c := range p.Status.InitContainerStatuses {
			id := stripContainerIDPrefix(c.ContainerID)
			if id != "" {
				byID[id] = ns
			}
		}
		// PodIP principal (status.podIP) + adicionais (status.podIPs[]).
		// Dual-stack: pode ter v4 + v6 — registramos os dois.
		if p.Status.PodIP != "" {
			byIP[p.Status.PodIP] = ns
		}
		for _, ip := range p.Status.PodIPs {
			if ip.IP != "" {
				byIP[ip.IP] = ns
			}
		}
	}
	return PodIndex{ByContainerID: byID, ByPodIP: byIP, ByNsPod: byNsPod}, nil
}

// stripContainerIDPrefix converte "containerd://abc..." em "abc...".
func stripContainerIDPrefix(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		return s[i+3:]
	}
	return s
}

// deriveWorkload resolve o workload (Deployment/StatefulSet/DaemonSet) do pod a
// partir dos ownerReferences, caindo na heurística por nome do pod quando não
// houver owner reconhecível. Deployment vem via ReplicaSet ("app-<rsHash>" →
// "app"); StatefulSet/DaemonSet/Job vêm pelo nome do owner direto.
func deriveWorkload(podName string, owners []podOwnerRef) string {
	for _, o := range owners {
		switch o.Kind {
		case "ReplicaSet":
			return k8smeta.WorkloadOf(o.Name + "-00000")
		case "StatefulSet", "DaemonSet", "Job":
			return k8smeta.WorkloadOf(o.Name)
		}
	}
	return k8smeta.WorkloadOf(podName)
}

// podOwnerRef — subset de metadata.ownerReferences[] do kubelet /pods.
type podOwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// kubeletPodList — subset do PodList do kubelet /pods.
type kubeletPodList struct {
	Items []struct {
		Metadata struct {
			Name            string            `json:"name"`
			Namespace       string            `json:"namespace"`
			Labels          map[string]string `json:"labels"`
			OwnerReferences []podOwnerRef     `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			PodIP  string `json:"podIP"`
			PodIPs []struct {
				IP string `json:"ip"`
			} `json:"podIPs"`
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"initContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}
