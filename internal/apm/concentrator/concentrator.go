// Package concentrator agrega spans em APM stats por bucket de tempo, com
// DDSketch de latência — a peça-núcleo do trace-agent (espelha o concentrator
// do Datadog).
//
// Garantia-chave: hits/errors e os sketches são contados ANTES de qualquer
// sampling. Por isso as estatísticas (p50/p95/p99, throughput, error-rate) são
// EXATAS mesmo que o agent guarde só 1 trace cru em N. O backend recebe os
// sketches no encoding nativo flag-based (mesmo formato do sketches-java) e só
// faz merge por bucket — sem reler spans.
package concentrator

import (
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/sketches-go/ddsketch"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	// BucketDuration é a janela de agregação (igual ao Datadog).
	BucketDuration = 10 * time.Second
	// relativeAccuracy do DDSketch — PRECISA bater com a outra ponta (backend)
	// pro merge ser válido. 1%.
	relativeAccuracy = 0.01
)

// GroupedStats é o snapshot de um grupo num bucket, pronto pro forwarder
// converter em ApmGroupedStats (proto). Os sketches já vêm serializados.
type GroupedStats struct {
	BucketStartUnixNano int64
	Env                 string
	Service             string
	Resource            string
	Operation           string
	SpanKind            int32
	HTTPStatusCode      int32
	Hits                uint64
	Errors              uint64
	DurationSumNano     uint64
	TopLevel            bool
	OkSummary           []byte // DDSketch (nanos) das latências OK; nil se vazio
	ErrorSummary        []byte // DDSketch (nanos) das latências de erro; nil se vazio
}

type bucketKey struct {
	env        string
	service    string
	resource   string
	operation  string
	spanKind   int32
	httpStatus int32
}

type groupStats struct {
	hits            uint64
	errors          uint64
	durationSumNano uint64
	topLevel        bool
	okSketch        *ddsketch.DDSketch
	errSketch       *ddsketch.DDSketch
}

// Concentrator acumula stats de forma thread-safe. Add roda no hot path (Push);
// Flush é chamado periodicamente pelo loop do trace-agent.
type Concentrator struct {
	mu      sync.Mutex
	buckets map[int64]map[bucketKey]*groupStats
	log     *slog.Logger
}

// New cria um concentrator vazio.
func New(log *slog.Logger) *Concentrator {
	if log == nil {
		log = slog.Default()
	}
	return &Concentrator{
		buckets: make(map[int64]map[bucketKey]*groupStats),
		log:     log.With("component", "apm-concentrator"),
	}
}

// Add contabiliza um span. Seguro no hot path. Spans inválidos são ignorados.
func (c *Concentrator) Add(s *collectorv1.Span) {
	if s == nil || s.StartUnixNano <= 0 || s.EndUnixNano < s.StartUnixNano {
		return
	}
	dur := s.EndUnixNano - s.StartUnixNano
	bucketStart := s.StartUnixNano - (s.StartUnixNano % int64(BucketDuration))
	k := bucketKey{
		env:        s.Attributes["deployment.environment"],
		service:    s.ServiceName,
		resource:   resourceOf(s),
		operation:  s.Name,
		spanKind:   s.Kind,
		httpStatus: httpStatusOf(s.Attributes),
	}
	isErr := s.StatusCode == 2 // OTLP ERROR

	c.mu.Lock()
	defer c.mu.Unlock()
	groups := c.buckets[bucketStart]
	if groups == nil {
		groups = make(map[bucketKey]*groupStats)
		c.buckets[bucketStart] = groups
	}
	g := groups[k]
	if g == nil {
		g = &groupStats{
			okSketch:  newSketch(),
			errSketch: newSketch(),
			topLevel:  s.Kind == 2 || s.Kind == 5, // SERVER ou CONSUMER = span de entrada
		}
		groups[k] = g
	}
	g.hits++
	g.durationSumNano += uint64(dur)
	if isErr {
		g.errors++
		_ = g.errSketch.Add(float64(dur))
	} else {
		_ = g.okSketch.Add(float64(dur))
	}
}

// Flush devolve todos os buckets acumulados e zera o estado. Reemitir o mesmo
// bucket (parcial) entre flushes é seguro: o backend mescla por bucket_start.
func (c *Concentrator) Flush() []GroupedStats {
	c.mu.Lock()
	buckets := c.buckets
	c.buckets = make(map[int64]map[bucketKey]*groupStats)
	c.mu.Unlock()

	var out []GroupedStats
	for bucketStart, groups := range buckets {
		for k, g := range groups {
			out = append(out, GroupedStats{
				BucketStartUnixNano: bucketStart,
				Env:                 k.env,
				Service:             k.service,
				Resource:            k.resource,
				Operation:           k.operation,
				SpanKind:            k.spanKind,
				HTTPStatusCode:      k.httpStatus,
				Hits:                g.hits,
				Errors:              g.errors,
				DurationSumNano:     g.durationSumNano,
				TopLevel:            g.topLevel,
				OkSummary:           encodeSketch(g.okSketch),
				ErrorSummary:        encodeSketch(g.errSketch),
			})
		}
	}
	return out
}

func newSketch() *ddsketch.DDSketch {
	s, _ := ddsketch.NewDefaultDDSketch(relativeAccuracy)
	return s
}

func encodeSketch(s *ddsketch.DDSketch) []byte {
	if s == nil || s.GetCount() == 0 {
		return nil
	}
	var b []byte
	s.Encode(&b, false) // false = inclui o index mapping (backend decoda sem saber o accuracy)
	return b
}

// resourceOf deriva o resource de baixa cardinalidade. Pra HTTP usa method+route;
// senão cai no nome da operação. (Normalização fina de path fica pro obfuscator.)
func resourceOf(s *collectorv1.Span) string {
	method := s.Attributes["http.request.method"]
	if method == "" {
		method = s.Attributes["http.method"]
	}
	route := s.Attributes["http.route"]
	if method != "" && route != "" {
		return method + " " + route
	}
	return s.Name
}

func httpStatusOf(attrs map[string]string) int32 {
	v := attrs["http.response.status_code"]
	if v == "" {
		v = attrs["http.status_code"]
	}
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return int32(n)
}
