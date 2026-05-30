// k8s_kubelet.go — Check "k8s.kubelet" (Phase k8s v1).
//
// Lê /stats/summary do kubelet local (mesma máquina onde o DaemonSet roda)
// e emite métricas de node + pods + containers pra VictoriaMetrics.
//
// Ciclo (1 Run) emite:
//
// Node-level (tag node=<nodeName>):
//   - k8s.node.cpu_usage_nanocores
//   - k8s.node.memory_working_set_bytes
//   - k8s.node.fs_used_bytes / k8s.node.fs_capacity_bytes
//   - k8s.node.network_rx_bytes / k8s.node.network_tx_bytes
//
// Pod-level (tags namespace, pod, node):
//   - k8s.pod.cpu_usage_nanocores
//   - k8s.pod.memory_working_set_bytes
//
// Container-level (tags namespace, pod, container, node):
//   - k8s.container.cpu_usage_nanocores
//   - k8s.container.memory_working_set_bytes
//   - k8s.container.rootfs_used_bytes / k8s.container.rootfs_capacity_bytes
//   - k8s.container.logs_used_bytes
//
// Storage por pod (tags namespace, pod, node):
//   - k8s.pod.ephemeral_storage_used_bytes
//   - k8s.pod.ephemeral_storage_capacity_bytes
//
// Storage por volume (tags namespace, pod, volume, [pvc], node):
//   - k8s.volume.used_bytes / k8s.volume.capacity_bytes
//   - k8s.volume.inodes_used
//
// Decisões locked:
//   - Auth: Bearer token do SA mount padrão (/var/run/secrets/.../token).
//     Pode ser override via Params["token_file"].
//   - TLS: usa ca.crt do SA mount; se ausente, cai pra InsecureSkipVerify
//     (kubelet usa cert self-signed; SkipVerify é aceitável quando o
//     agent roda na mesma máquina).
//   - Endpoint: Params["kubelet_url"] (default https://localhost:10250).
//     DaemonSet com hostNetwork=true permite usar localhost; sem
//     hostNetwork seria ${HOST_IP}:10250 vindo de downward API.
//   - Best-effort: pod com payload corrompido é skipado silenciosamente;
//     restante ainda emite. Falha de HTTP/parse propaga como erro do Run
//     pra acionar circuit-breaker do scheduler.

package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultKubeletInterval = 15 * time.Second
	defaultKubeletURL      = "https://localhost:10250"
	defaultTokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubeletReadTimeout     = 8 * time.Second
)

// kubeletSummary espelha o subset de /stats/summary que consumimos.
// Campos não mapeados são ignorados pelo json decoder.
type kubeletSummary struct {
	Node struct {
		NodeName string `json:"nodeName"`
		CPU      struct {
			UsageNanoCores *uint64 `json:"usageNanoCores"`
		} `json:"cpu"`
		Memory struct {
			WorkingSetBytes *uint64 `json:"workingSetBytes"`
		} `json:"memory"`
		Network struct {
			RxBytes *uint64 `json:"rxBytes"`
			TxBytes *uint64 `json:"txBytes"`
		} `json:"network"`
		Fs struct {
			UsedBytes     *uint64 `json:"usedBytes"`
			CapacityBytes *uint64 `json:"capacityBytes"`
		} `json:"fs"`
	} `json:"node"`
	Pods []kubeletPodSummary `json:"pods"`
}

type kubeletFsStats struct {
	UsedBytes     *uint64 `json:"usedBytes"`
	CapacityBytes *uint64 `json:"capacityBytes"`
	InodesUsed    *uint64 `json:"inodesUsed"`
}

type kubeletVolumeStats struct {
	Name          string  `json:"name"`
	UsedBytes     *uint64 `json:"usedBytes"`
	CapacityBytes *uint64 `json:"capacityBytes"`
	InodesUsed    *uint64 `json:"inodesUsed"`
	PVCRef        *struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"pvcRef,omitempty"`
}

type kubeletPodSummary struct {
	PodRef struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"podRef"`
	CPU struct {
		UsageNanoCores *uint64 `json:"usageNanoCores"`
	} `json:"cpu"`
	Memory struct {
		WorkingSetBytes *uint64 `json:"workingSetBytes"`
	} `json:"memory"`
	Containers []struct {
		Name string `json:"name"`
		CPU  struct {
			UsageNanoCores *uint64 `json:"usageNanoCores"`
		} `json:"cpu"`
		Memory struct {
			WorkingSetBytes *uint64 `json:"workingSetBytes"`
		} `json:"memory"`
		Rootfs *kubeletFsStats `json:"rootfs,omitempty"`
		Logs   *kubeletFsStats `json:"logs,omitempty"`
	} `json:"containers"`
	Volume           []kubeletVolumeStats `json:"volume,omitempty"`
	EphemeralStorage *kubeletFsStats      `json:"ephemeral-storage,omitempty"`
}

// kubeletFetcher é a interface seam — testes injetam fake; em prod
// usa httpKubeletFetcher real.
type kubeletFetcher interface {
	Summary(ctx context.Context) (*kubeletSummary, error)
}

type httpKubeletFetcher struct {
	url    string
	token  string
	client *http.Client
}

func newHTTPKubeletFetcher(url, tokenFile, caFile string, insecure bool) (*httpKubeletFetcher, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
	if caFile != "" && !insecure {
		ca, err := os.ReadFile(caFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(ca) {
				tlsCfg = &tls.Config{RootCAs: pool}
			}
		}
		// se falhar lê CA, cai pra InsecureSkipVerify silenciosamente —
		// kubelet local quase sempre tem cert self-signed.
		if tlsCfg.RootCAs == nil {
			tlsCfg = &tls.Config{InsecureSkipVerify: true}
		}
	}

	var token string
	if tokenFile != "" {
		if b, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}

	return &httpKubeletFetcher{
		url:   strings.TrimRight(url, "/") + "/stats/summary",
		token: token,
		client: &http.Client{
			Timeout: kubeletReadTimeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConnsPerHost: 2,
			},
		},
	}, nil
}

func (h *httpKubeletFetcher) Summary(ctx context.Context) (*kubeletSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("kubelet new req: %w", err)
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubelet GET %s: %w", h.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("kubelet GET %s: status %d body=%q",
			h.url, resp.StatusCode, body)
	}

	var sum kubeletSummary
	if err := json.NewDecoder(resp.Body).Decode(&sum); err != nil {
		return nil, fmt.Errorf("kubelet decode: %w", err)
	}
	return &sum, nil
}

type k8sKubeletCheck struct {
	id         string
	hostID     string
	interval   time.Duration
	staticTags map[string]string
	fetcher    kubeletFetcher
}

func newK8sKubeletCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()

	url := strings.TrimSpace(params["kubelet_url"])
	if url == "" {
		url = defaultKubeletURL
	}
	tokenFile := strings.TrimSpace(params["token_file"])
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	caFile := strings.TrimSpace(params["ca_file"])
	if caFile == "" {
		caFile = defaultCAFile
	}
	insecure := params["insecure_skip_verify"] == "true"

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultKubeletInterval
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "k8s.kubelet-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	fetcher, err := newHTTPKubeletFetcher(url, tokenFile, caFile, insecure)
	if err != nil {
		return nil, fmt.Errorf("k8s.kubelet: %w", err)
	}

	return &k8sKubeletCheck{
		id:         id,
		hostID:     cfg.GetHostId(),
		interval:   interval,
		staticTags: tags,
		fetcher:    fetcher,
	}, nil
}

func (c *k8sKubeletCheck) ID() string              { return c.id }
func (c *k8sKubeletCheck) Interval() time.Duration { return c.interval }
func (c *k8sKubeletCheck) Tags() map[string]string { return c.staticTags }

func (c *k8sKubeletCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	sum, err := c.fetcher.Summary(ctx)
	if err != nil {
		return nil, err
	}

	now := timestamppb.Now()
	out := make([]*collectorv1.Metric, 0, 64)

	nodeName := sum.Node.NodeName
	nodeTags := map[string]string{"node": nodeName}

	addNode := func(name string, p *uint64) {
		if p == nil {
			return
		}
		out = append(out, c.metric(now, name, float64(*p), nodeTags))
	}
	addNode("k8s.node.cpu_usage_nanocores", sum.Node.CPU.UsageNanoCores)
	addNode("k8s.node.memory_working_set_bytes", sum.Node.Memory.WorkingSetBytes)
	addNode("k8s.node.network_rx_bytes", sum.Node.Network.RxBytes)
	addNode("k8s.node.network_tx_bytes", sum.Node.Network.TxBytes)
	addNode("k8s.node.fs_used_bytes", sum.Node.Fs.UsedBytes)
	addNode("k8s.node.fs_capacity_bytes", sum.Node.Fs.CapacityBytes)

	// pod count breakdown
	podCount := 0
	for _, p := range sum.Pods {
		if p.PodRef.Name == "" {
			continue
		}
		podCount++
		podTags := map[string]string{
			"node":      nodeName,
			"namespace": p.PodRef.Namespace,
			"pod":       p.PodRef.Name,
		}
		if p.CPU.UsageNanoCores != nil {
			out = append(out, c.metric(now, "k8s.pod.cpu_usage_nanocores",
				float64(*p.CPU.UsageNanoCores), podTags))
		}
		if p.Memory.WorkingSetBytes != nil {
			out = append(out, c.metric(now, "k8s.pod.memory_working_set_bytes",
				float64(*p.Memory.WorkingSetBytes), podTags))
		}
		// Pod ephemeral storage (somatório de rootfs + logs + emptyDir local).
		if p.EphemeralStorage != nil {
			if p.EphemeralStorage.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.ephemeral_storage_used_bytes",
					float64(*p.EphemeralStorage.UsedBytes), podTags))
			}
			if p.EphemeralStorage.CapacityBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.ephemeral_storage_capacity_bytes",
					float64(*p.EphemeralStorage.CapacityBytes), podTags))
			}
		}
		// Volumes do pod — emptyDir, configMap, secret, PVC, etc.
		for _, vol := range p.Volume {
			if vol.Name == "" {
				continue
			}
			volTags := map[string]string{
				"node":      nodeName,
				"namespace": p.PodRef.Namespace,
				"pod":       p.PodRef.Name,
				"volume":    vol.Name,
			}
			if vol.PVCRef != nil && vol.PVCRef.Name != "" {
				volTags["pvc"] = vol.PVCRef.Name
			}
			if vol.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.volume.used_bytes",
					float64(*vol.UsedBytes), volTags))
			}
			if vol.CapacityBytes != nil {
				out = append(out, c.metric(now, "k8s.volume.capacity_bytes",
					float64(*vol.CapacityBytes), volTags))
			}
			if vol.InodesUsed != nil {
				out = append(out, c.metric(now, "k8s.volume.inodes_used",
					float64(*vol.InodesUsed), volTags))
			}
		}
		for _, ct := range p.Containers {
			if ct.Name == "" {
				continue
			}
			ctTags := map[string]string{
				"node":      nodeName,
				"namespace": p.PodRef.Namespace,
				"pod":       p.PodRef.Name,
				"container": ct.Name,
			}
			if ct.CPU.UsageNanoCores != nil {
				out = append(out, c.metric(now, "k8s.container.cpu_usage_nanocores",
					float64(*ct.CPU.UsageNanoCores), ctTags))
			}
			if ct.Memory.WorkingSetBytes != nil {
				out = append(out, c.metric(now, "k8s.container.memory_working_set_bytes",
					float64(*ct.Memory.WorkingSetBytes), ctTags))
			}
			if ct.Rootfs != nil {
				if ct.Rootfs.UsedBytes != nil {
					out = append(out, c.metric(now, "k8s.container.rootfs_used_bytes",
						float64(*ct.Rootfs.UsedBytes), ctTags))
				}
				if ct.Rootfs.CapacityBytes != nil {
					out = append(out, c.metric(now, "k8s.container.rootfs_capacity_bytes",
						float64(*ct.Rootfs.CapacityBytes), ctTags))
				}
			}
			if ct.Logs != nil && ct.Logs.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.container.logs_used_bytes",
					float64(*ct.Logs.UsedBytes), ctTags))
			}
		}
	}
	out = append(out, c.metric(now, "k8s.node.pods_total", float64(podCount), nodeTags))

	return out, nil
}

func (c *k8sKubeletCheck) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+len(extraTags))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "k8s.kubelet",
	}
}

// init auto-registra o factory. Mesma pattern dos outros checks.
func init() {
	Default.Register("k8s.kubelet", newK8sKubeletCheck)
}
