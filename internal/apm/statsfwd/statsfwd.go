// Package statsfwd converte os GroupedStats do concentrator em ApmStatsPayload
// (proto) e envia ao backend via POST /api/ingest/v1/apm/stats — certless,
// Bearer token, content-type application/x-protobuf. É a ponta que fala com o
// ApmStatsIngestor do isp-watch.
package statsfwd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ispwatch/collector/internal/apm/concentrator"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Forwarder envia APM stats ao endpoint de ingest.
type Forwarder struct {
	client       *http.Client
	url          string
	token        string
	agentVersion string
	log          *slog.Logger
}

// New cria um Forwarder. baseURL é a raiz do ingest (ex.: https://telvyn.../).
func New(client *http.Client, baseURL, token, agentVersion string, log *slog.Logger) *Forwarder {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Forwarder{
		client:       client,
		url:          strings.TrimRight(baseURL, "/") + "/api/ingest/v1/apm/stats",
		token:        token,
		agentVersion: agentVersion,
		log:          log.With("component", "apm-stats-forwarder"),
	}
}

// Send converte os grupos em ApmStatsPayload e faz POST. No-op se vazio.
func (f *Forwarder) Send(ctx context.Context, groups []concentrator.GroupedStats) error {
	if len(groups) == 0 {
		return nil
	}
	body, err := proto.Marshal(buildPayload(f.agentVersion, groups))
	if err != nil {
		return fmt.Errorf("marshal apm stats: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+f.token)

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("post apm stats: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("apm stats rejeitado: status %d", resp.StatusCode)
	}
	f.log.Debug("apm stats enviados", "groups", len(groups), "bytes", len(body))
	return nil
}

func buildPayload(agentVersion string, groups []concentrator.GroupedStats) *collectorv1.ApmStatsPayload {
	byBucket := make(map[int64][]*collectorv1.ApmGroupedStats)
	for _, g := range groups {
		byBucket[g.BucketStartUnixNano] = append(byBucket[g.BucketStartUnixNano], &collectorv1.ApmGroupedStats{
			Env:             g.Env,
			Service:         g.Service,
			Resource:        g.Resource,
			Operation:       g.Operation,
			SpanKind:        g.SpanKind,
			HttpStatusCode:  g.HTTPStatusCode,
			Hits:            g.Hits,
			Errors:          g.Errors,
			DurationSumNano: g.DurationSumNano,
			OkSummary:       g.OkSummary,
			ErrorSummary:    g.ErrorSummary,
			TopLevel:        g.TopLevel,
			Source:          g.Source,
			DbSystem:        g.DbSystem,
			Namespace:       g.Namespace,
		})
	}
	payload := &collectorv1.ApmStatsPayload{AgentVersion: agentVersion}
	for bucketStart, stats := range byBucket {
		payload.Buckets = append(payload.Buckets, &collectorv1.ApmStatsBucket{
			StartUnixNano: bucketStart,
			DurationNano:  int64(concentrator.BucketDuration),
			Stats:         stats,
		})
	}
	return payload
}
