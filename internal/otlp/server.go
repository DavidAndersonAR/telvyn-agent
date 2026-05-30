// Package otlp implementa um receiver OTLP/gRPC mínimo (porta 4317 por
// default) que coleta spans de processos co-localizados no nó (Java/Quarkus
// instrumentados via -javaagent injetado pelo webhook do agent).
//
// Decisões locked:
//
//   - Sem TLS no listener — pods do mesmo nó alcançam via $(NODE_IP):4317
//     (DaemonSet com hostPort). O TLS acontece no próximo hop (agent →
//     backend via mTLS já configurado).
//
//   - Reusa types proto da SDK OTel (go.opentelemetry.io/proto/otlp) ao
//     invés de duplicar — já é dep transitive do agent.
//
//   - Buffer in-memory por enquanto (sink push síncrono). Sem WAL pra spans
//     nesta versão — perdemos spans se o agent reiniciar antes do flush
//     do forwarder. OK pra dev/lab. WAL pode ser adicionado depois
//     (mesma infra do bbolt usada pra métricas).
//
//   - Mapeamento OTLP Span → nosso collectorv1.Span é opinativo:
//     atributos não-string serializados via fmt.Sprint, span events/links
//     são ignorados nesta versão.
package otlp

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"

	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	// DefaultListenAddr — bind no host do nó. Pods do mesmo nó
	// (instrumentados pelo nosso webhook) usam $(NODE_IP):4317.
	DefaultListenAddr = "0.0.0.0:4317"

	// MaxRecvMsgSize cap defensivo. OTLP raramente passa 4MB; 16 dá folga.
	maxRecvMsgSize = 16 * 1024 * 1024
)

// SpanSink recebe batches de spans convertidos. Implementado pelo
// forwarder que envia via gRPC StreamSpans pro backend. Separar interface
// deixa o receiver testável sem mockar gRPC.
type SpanSink interface {
	Push(spans []*collectorv1.Span)
}

// Receiver é o server OTLP/gRPC que escuta na porta 4317 e converte cada
// ExportTraceServiceRequest em []*collectorv1.Span pro sink.
type Receiver struct {
	tracepb.UnimplementedTraceServiceServer

	addr   string
	sink   SpanSink
	log    *slog.Logger
	server *grpc.Server

	mu       sync.Mutex
	received int64
}

func NewReceiver(addr string, sink SpanSink, log *slog.Logger) *Receiver {
	if addr == "" {
		addr = DefaultListenAddr
	}
	return &Receiver{
		addr: addr,
		sink: sink,
		log:  log.With("component", "otlp-receiver"),
	}
}

// Start abre listener e roda o server até o ctx ser cancelado.
// Falha de bind retorna erro imediato.
func (r *Receiver) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", r.addr)
	if err != nil {
		return fmt.Errorf("otlp listen %s: %w", r.addr, err)
	}

	r.server = grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
	)
	tracepb.RegisterTraceServiceServer(r.server, r)

	r.log.Info("otlp gRPC receiver listening", "addr", r.addr)

	errCh := make(chan error, 1)
	go func() {
		if err := r.server.Serve(lis); err != nil {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		r.log.Info("otlp receiver shutting down")
		done := make(chan struct{})
		go func() {
			r.server.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			r.log.Warn("graceful stop timed out, forcing")
			r.server.Stop()
		}
		return nil
	case err := <-errCh:
		if err != nil {
			r.log.Error("otlp serve failed", "err", err)
		}
		return err
	}
}

// Stats devolve contador cumulativo pra self-metrics.
func (r *Receiver) Stats() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received
}

// Export implementa tracepb.TraceServiceServer.Export. Converte OTLP spans
// pro nosso formato compacto e push pro sink.
func (r *Receiver) Export(ctx context.Context, req *tracepb.ExportTraceServiceRequest) (*tracepb.ExportTraceServiceResponse, error) {
	if req == nil {
		return &tracepb.ExportTraceServiceResponse{}, nil
	}
	var spans []*collectorv1.Span
	for _, rs := range req.ResourceSpans {
		resAttrs := flattenAttrs(rs.Resource.GetAttributes())
		serviceName := resAttrs["service.name"]
		namespace := resAttrs["k8s.namespace.name"]
		pod := resAttrs["k8s.pod.name"]
		if serviceName == "" {
			serviceName = pod
		}
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				cs := &collectorv1.Span{
					TraceId:       hex.EncodeToString(s.TraceId),
					SpanId:        hex.EncodeToString(s.SpanId),
					ParentSpanId:  hex.EncodeToString(s.ParentSpanId),
					ServiceName:   serviceName,
					Name:          s.Name,
					Kind:          int32(s.Kind),
					StartUnixNano: int64(s.StartTimeUnixNano),
					EndUnixNano:   int64(s.EndTimeUnixNano),
					Namespace:     namespace,
					Pod:           pod,
					Attributes:    flattenAttrs(s.Attributes),
				}
				if s.Status != nil {
					cs.StatusCode = int32(s.Status.Code)
					cs.StatusMessage = s.Status.Message
				}
				// Anexa resource attrs úteis (http.*, db.*) sem sobrescrever
				// attrs já presentes do span.
				for k, v := range resAttrs {
					if _, ok := cs.Attributes[k]; !ok {
						cs.Attributes[k] = v
					}
				}
				spans = append(spans, cs)
			}
		}
	}
	r.mu.Lock()
	r.received += int64(len(spans))
	r.mu.Unlock()

	if len(spans) > 0 && r.sink != nil {
		r.sink.Push(spans)
	}
	return &tracepb.ExportTraceServiceResponse{}, nil
}

// flattenAttrs reduz a slice de KeyValue OTLP num map[string]string.
// Tipos não-string viram texto via fmt.Sprint pra simplificar o storage.
// Listas/maps são serializadas em formato compacto — em prática raras.
func flattenAttrs(in []*commonpb.KeyValue) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for _, kv := range in {
		if kv == nil || kv.Key == "" {
			continue
		}
		out[kv.Key] = anyValueToString(kv.Value)
	}
	return out
}

func anyValueToString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch x := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'f', -1, 64)
	case *commonpb.AnyValue_BytesValue:
		return hex.EncodeToString(x.BytesValue)
	case *commonpb.AnyValue_ArrayValue:
		if x.ArrayValue == nil {
			return "[]"
		}
		parts := make([]string, 0, len(x.ArrayValue.Values))
		for _, item := range x.ArrayValue.Values {
			parts = append(parts, anyValueToString(item))
		}
		return "[" + joinComma(parts) + "]"
	case *commonpb.AnyValue_KvlistValue:
		if x.KvlistValue == nil {
			return "{}"
		}
		parts := make([]string, 0, len(x.KvlistValue.Values))
		for _, kv := range x.KvlistValue.Values {
			parts = append(parts, kv.Key+"="+anyValueToString(kv.Value))
		}
		return "{" + joinComma(parts) + "}"
	}
	return ""
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
