// ingest.go — modo "Datadog-style": manda telemetria pro gateway OTLP do
// Telvyn (/api/ingest/v1) autenticando com um Bearer token reusável (iwI_),
// sobre HTTP simples. SEM mTLS, sem cert por agent, sem enrollment.
//
// Dois caminhos:
//   - PostRaw: encaminha o corpo OTLP cru recebido pelo receiver (spans,
//     logs, metrics de apps) — zero conversão.
//   - PostMetrics: converte as métricas nativas do host (CPU/mem/disco/rede
//     dos self-checks) pra OTLP metrics e manda pro /metrics.
//
// É o equivalente exato do modelo do Datadog agent: API key + HTTPS, o
// servidor identifica o tenant pelo token.

package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/encoding/protojson"

	metricscolpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// IngestExporter envia OTLP pro gateway com Bearer token.
type IngestExporter struct {
	base        string // ex: http://telvyn.host/api/ingest/v1 (sem barra final)
	token       string
	hostID      string
	clusterName string
	client      *http.Client
	log         *slog.Logger
}

// NewIngestExporter. base = URL do gateway (com ou sem /api/ingest/v1 — a
// gente normaliza). token = ingest token iwI_. hostID/cluster viram resource
// attrs nas métricas convertidas.
func NewIngestExporter(base, token, hostID, clusterName string, log *slog.Logger) *IngestExporter {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if !strings.HasSuffix(base, "/api/ingest/v1") {
		base = base + "/api/ingest/v1"
	}
	return &IngestExporter{
		base:        base,
		token:       strings.TrimSpace(token),
		hostID:      hostID,
		clusterName: clusterName,
		client:      &http.Client{Timeout: 20 * time.Second},
		log:         log.With("component", "ingest-exporter"),
	}
}

// PostRaw encaminha um corpo OTLP já codificado pro signal indicado
// ("traces" | "metrics" | "logs"), preservando o Content-Type original.
func (e *IngestExporter) PostRaw(ctx context.Context, signal, contentType string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	url := e.base + "/" + signal
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/x-protobuf"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ingest %s: HTTP %d", signal, resp.StatusCode)
	}
	return nil
}

// PostMetrics converte métricas nativas → OTLP Gauge e manda pro /metrics.
func (e *IngestExporter) PostMetrics(ctx context.Context, metrics []*collectorv1.Metric) error {
	if len(metrics) == 0 {
		return nil
	}
	dps := make([]*metricspb.Metric, 0, len(metrics))
	for _, m := range metrics {
		if m == nil || m.GetMetricName() == "" {
			continue
		}
		var tsNano uint64
		if m.GetTime() != nil {
			tsNano = uint64(m.GetTime().AsTime().UnixNano())
		} else {
			tsNano = uint64(time.Now().UnixNano())
		}
		attrs := make([]*commonpb.KeyValue, 0, len(m.GetTags())+3)
		for k, v := range m.GetTags() {
			attrs = append(attrs, kv(k, v))
		}
		if h := m.GetHostId(); h != "" {
			attrs = append(attrs, kv("host.id", h))
		}
		if iface := m.GetInterfaceName(); iface != "" {
			attrs = append(attrs, kv("interface", iface))
		}
		if src := m.GetSource(); src != "" {
			attrs = append(attrs, kv("source", src))
		}
		dps = append(dps, &metricspb.Metric{
			Name: m.GetMetricName(),
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: tsNano,
					Attributes:   attrs,
					Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: m.GetValue()},
				}},
			}},
		})
	}
	if len(dps) == 0 {
		return nil
	}
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		kv("service.name", "telvyn-agent"),
		kv("host.name", e.hostID),
	}}
	if e.clusterName != "" {
		res.Attributes = append(res.Attributes, kv("k8s.cluster.name", e.clusterName))
	}
	reqMsg := &metricscolpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource:     res,
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: dps}},
		}},
	}
	// Gateway OTLP do Telvyn é JSON-only (igual /traces) — manda protojson.
	body, err := protojson.Marshal(reqMsg)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "metrics", "application/json", body)
}

// PostSnmpTrap encaminha um SNMP trap já parseado pro backend (noc_device_event).
// O backend mapeia source_ip→host e classifica o trap_oid (severity + mensagem).
func (e *IngestExporter) PostSnmpTrap(ctx context.Context, trap map[string]any) error {
	if len(trap) == 0 {
		return nil
	}
	body, err := json.Marshal(trap)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "snmptrap", "application/json", body)
}

// PostK8sEvents encaminha um lote de eventos do Kubernetes pro gateway
// (noc_k8s_event, Cluster Agent F2). O payload já vem no shape do endpoint
// {"cluster": ..., "events": [{...}]}; o backend deriva o tenant do token e
// deduplica por (cluster, namespace, pod, reason, involved_name) agregando o
// count nativo do k8s. Molde de PostSnmpTrap — JSON + Bearer, check 2xx.
func (e *IngestExporter) PostK8sEvents(ctx context.Context, payload map[string]any) error {
	if len(payload) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "k8s/events", "application/json", body)
}

// ---- Logs (OTLP JSON) -------------------------------------------------

// Shapes JSON do OTLP logs export (resourceLogs → scopeLogs → logRecords).
// Construímos à mão (sem dep do proto otlp/logs) porque o gateway Quarkus
// parseia via Jackson — só precisa do shape, não do protobuf. Espelha o que
// parseOtlpJsonLogs espera: service.name/host.name/k8s.* em resource attrs,
// body.stringValue, timeUnixNano como string, severityNumber como número.
type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpLogResource `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpLogResource struct {
	Attributes []otlpLogKV `json:"attributes"`
}

type otlpScopeLogs struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpLogRecord struct {
	TimeUnixNano   string       `json:"timeUnixNano"`
	SeverityNumber int          `json:"severityNumber,omitempty"`
	SeverityText   string       `json:"severityText,omitempty"`
	Body           otlpLogValue `json:"body"`
	TraceID        string       `json:"traceId,omitempty"`
	SpanID         string       `json:"spanId,omitempty"`
	Attributes     []otlpLogKV  `json:"attributes,omitempty"`
}

// otlpLogKV / otlpLogValue: shapes próprios dos logs (o http.go já tem um
// otlpKeyValue do receiver de spans, com Value inline — por isso prefixo Log).
type otlpLogKV struct {
	Key   string       `json:"key"`
	Value otlpLogValue `json:"value"`
}

type otlpLogValue struct {
	StringValue string `json:"stringValue"`
}

func logKV(k, v string) otlpLogKV {
	return otlpLogKV{Key: k, Value: otlpLogValue{StringValue: v}}
}

// PostLogs converte LogRecords internos → OTLP JSON e manda pro /logs com
// Bearer. Agrupa por (service, namespace, pod) em ResourceLogs distintos —
// o backend lê service.name do resource attr e namespace/pod do attr mesclado,
// então o agrupamento dá service_name correto por pod. k8s.container.name e
// outros attrs ficam no log record (variam por linha dentro do pod).
func (e *IngestExporter) PostLogs(ctx context.Context, records []LogRecord) error {
	if len(records) == 0 {
		return nil
	}
	var payload otlpLogsPayload
	groups := make(map[string]int, 8) // chave → índice em payload.ResourceLogs
	for _, r := range records {
		ns := r.Attributes["k8s.namespace.name"]
		pod := r.Attributes["k8s.pod.name"]
		svc := r.ServiceName
		host := r.Hostname
		if host == "" {
			host = e.hostID
		}
		key := svc + "\x00" + ns + "\x00" + pod + "\x00" + host
		idx, ok := groups[key]
		if !ok {
			resAttrs := make([]otlpLogKV, 0, 5)
			if svc != "" {
				resAttrs = append(resAttrs, logKV("service.name", svc))
			}
			if host != "" {
				resAttrs = append(resAttrs, logKV("host.name", host))
			}
			if ns != "" {
				resAttrs = append(resAttrs, logKV("k8s.namespace.name", ns))
			}
			if pod != "" {
				resAttrs = append(resAttrs, logKV("k8s.pod.name", pod))
			}
			if e.clusterName != "" {
				resAttrs = append(resAttrs, logKV("k8s.cluster.name", e.clusterName))
			}
			payload.ResourceLogs = append(payload.ResourceLogs, otlpResourceLogs{
				Resource:  otlpLogResource{Attributes: resAttrs},
				ScopeLogs: []otlpScopeLogs{{}},
			})
			idx = len(payload.ResourceLogs) - 1
			groups[key] = idx
		}
		// Attrs do record: tudo menos os que viraram resource attr (evita dup).
		recAttrs := make([]otlpLogKV, 0, len(r.Attributes))
		for k, v := range r.Attributes {
			switch k {
			case "k8s.namespace.name", "k8s.pod.name", "service.name", "host.name":
				continue
			}
			recAttrs = append(recAttrs, logKV(k, v))
		}
		rec := otlpLogRecord{
			TimeUnixNano:   strconv.FormatInt(r.TimestampUnixNano, 10),
			SeverityNumber: r.SeverityNumber,
			SeverityText:   r.SeverityText,
			Body:           otlpLogValue{StringValue: r.Body},
			TraceID:        r.TraceID,
			SpanID:         r.SpanID,
			Attributes:     recAttrs,
		}
		sl := &payload.ResourceLogs[idx].ScopeLogs[0]
		sl.LogRecords = append(sl.LogRecords, rec)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "logs", "application/json", body)
}

// PostDeviceMetadata envia a identidade do device (metadata.device) pro gateway,
// que faz upsert no noc_device. Fiel ao Datadog (metadata.device).
func (e *IngestExporter) PostDeviceMetadata(ctx context.Context, hostID string, device map[string]string) error {
	if len(device) == 0 {
		return nil
	}
	payload := map[string]any{
		"host_id": hostID,
		"device":  device,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "device-metadata", "application/json", body)
}

// PostDeviceConfig envia a running-config coletada por SSH pro gateway (NCM),
// que sanitiza → versiona por hash em noc_device_config. v1 é SÓ LEITURA — o
// agente nunca reescreve o equipamento. host_id é o bigint do noc_host (string;
// o backend coage). vendor orienta a sanitização de linhas voláteis no backend.
func (e *IngestExporter) PostDeviceConfig(ctx context.Context, hostID, vendor, source, rawText, hostKey string) error {
	if rawText == "" {
		return nil
	}
	payload := map[string]any{
		"host_id":  hostID,
		"vendor":   vendor,
		"source":   source,
		"raw_text": rawText,
	}
	// TOFU: reporta a host key SSH observada pro backend fixar (só no 1º backup).
	if hostKey != "" {
		payload["host_key"] = hostKey
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "ncm/config", "application/json", body)
}

// RegisterK8sNode registra o nó no backend (POST /k8s/register, Bearer) →
// cria o noc_host + check k8s.kubelet (faz o nó aparecer em "Aplicações").
// Devolve o host_id (bigint como string) pra taggear as métricas de pod.
func (e *IngestExporter) RegisterK8sNode(ctx context.Context, cluster, node, nodeIP, k8sVersion string) (string, error) {
	payload := map[string]string{
		"cluster": cluster, "node": node, "node_ip": nodeIP, "k8s_version": k8sVersion,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/k8s/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("k8s register: HTTP %d", resp.StatusCode)
	}
	var out struct {
		HostID json.Number `json:"host_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.HostID.String(), nil
}

// RegisterCollector registra/atualiza o collector deste agente no backend
// (POST /collector/register, Bearer) → upsert em noc_collector por (tenant,
// name). Devolve o collector_id (UUID) + tenant, que o agente usa no
// config-pull (Bearer) pra puxar as checagens agendadas que o usuário criou.
func (e *IngestExporter) RegisterCollector(ctx context.Context, name string, capabilities []string) (string, string, error) {
	if capabilities == nil {
		capabilities = []string{}
	}
	payload := map[string]any{"name": name, "capabilities": capabilities}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/collector/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("collector register: HTTP %d", resp.StatusCode)
	}
	var out struct {
		CollectorID string `json:"collector_id"`
		Tenant      string `json:"tenant"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.CollectorID, out.Tenant, nil
}

func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}
