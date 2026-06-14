package concentrator

import (
	"testing"

	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/DataDog/sketches-go/ddsketch/store"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const ms = int64(1_000_000) // 1ms em nanos

func span(service string, start, end int64, status int32, attrs map[string]string) *collectorv1.Span {
	return &collectorv1.Span{
		ServiceName:   service,
		Name:          "GET /x",
		Kind:          2, // SERVER
		StartUnixNano: start,
		EndUnixNano:   end,
		StatusCode:    status,
		Attributes:    attrs,
	}
}

func TestConcentrator_HitsErrorsEQuantis(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000) // alinhado a 10s
	// 4 OK (10,20,30,40ms) + 1 erro (100ms) no mesmo bucket/grupo
	c.Add(span("svc", base, base+10*ms, 1, nil))
	c.Add(span("svc", base, base+20*ms, 1, nil))
	c.Add(span("svc", base, base+30*ms, 1, nil))
	c.Add(span("svc", base, base+40*ms, 1, nil))
	c.Add(span("svc", base, base+100*ms, 2, nil)) // erro

	out := c.Flush()
	if len(out) != 1 {
		t.Fatalf("esperava 1 grupo, veio %d", len(out))
	}
	g := out[0]
	if g.Hits != 5 || g.Errors != 1 {
		t.Fatalf("hits/errors errados: hits=%d errors=%d", g.Hits, g.Errors)
	}
	if g.Service != "svc" || !g.TopLevel {
		t.Fatalf("service/topLevel errados: %q topLevel=%v", g.Service, g.TopLevel)
	}
	if g.DurationSumNano != uint64((10+20+30+40+100)*ms) {
		t.Fatalf("durationSum errado: %d", g.DurationSumNano)
	}
	// p95 das OK deve cair na cauda alta (entre ~30 e 40ms; o DDSketch tem 1%
	// de erro relativo, então o piso é folgado).
	okP95 := quantile(t, g.OkSummary, 0.95)
	if okP95 < 25*float64(ms) || okP95 > 41*float64(ms) {
		t.Fatalf("p95 OK fora da faixa: %.0f ns", okP95)
	}
	// o sketch de erro tem só 1 valor (100ms)
	errP50 := quantile(t, g.ErrorSummary, 0.5)
	if errP50 < 99*float64(ms) || errP50 > 101*float64(ms) {
		t.Fatalf("p50 erro fora da faixa: %.0f ns", errP50)
	}
	// flush zerou o estado
	if got := len(c.Flush()); got != 0 {
		t.Fatalf("flush não zerou: %d", got)
	}
}

func TestConcentrator_BucketsSeparados(t *testing.T) {
	c := New(nil)
	b1 := int64(1_700_000_000_000_000_000)        // alinhado
	b2 := b1 + int64(BucketDuration) + 1          // próximo bucket de 10s
	c.Add(span("svc", b1, b1+ms, 1, nil))
	c.Add(span("svc", b2, b2+ms, 1, nil))
	if got := len(c.Flush()); got != 2 {
		t.Fatalf("esperava 2 buckets, veio %d", got)
	}
}

func TestConcentrator_AgrupaPorHTTPStatusEResource(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000)
	c.Add(span("svc", base, base+ms, 1, map[string]string{"http.request.method": "GET", "http.route": "/a", "http.response.status_code": "200"}))
	c.Add(span("svc", base, base+ms, 1, map[string]string{"http.request.method": "GET", "http.route": "/a", "http.response.status_code": "500"}))
	out := c.Flush()
	if len(out) != 2 { // mesmo resource, status diferente → 2 grupos
		t.Fatalf("esperava 2 grupos por status, veio %d", len(out))
	}
	for _, g := range out {
		if g.Resource != "GET /a" {
			t.Fatalf("resource errado: %q", g.Resource)
		}
	}
}

func quantile(t *testing.T, encoded []byte, q float64) float64 {
	t.Helper()
	if len(encoded) == 0 {
		t.Fatalf("sketch vazio")
	}
	s, err := ddsketch.DecodeDDSketch(encoded, store.DefaultProvider, nil)
	if err != nil {
		t.Fatalf("decode falhou: %v", err)
	}
	v, err := s.GetValueAtQuantile(q)
	if err != nil {
		t.Fatalf("quantile falhou: %v", err)
	}
	return v
}
