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
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/proto"

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
	body, err := proto.Marshal(reqMsg)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "metrics", "application/x-protobuf", body)
}

func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}
