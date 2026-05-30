// tagger.go — middleware de cardinality budget per-host para o Runtime.emit.
//
// O Tagger limita a quantidade de séries únicas que cada host pode emitir,
// dropando séries excedentes e gerando uma meta-métrica `ispwatch.tagger.dropped`
// que sinaliza o evento ao operador.
//
// Escopo per-host (não per-tenant): decisão locked no CONTEXT.md da Phase 3,
// que prevalece sobre o texto literal de REQ-CHECK-06 ("por tenant"). Per-host
// é o nível certo de isolamento porque um device exótico (DSLAM com 10k portas,
// switch core com 5k VLANs) não pode consumir o budget de hosts bem-comportados
// no mesmo tenant. Tag `tenant` no Metric é propagada pelo pipeline downstream.
//
// Algoritmo:
//   - map[hostID]map[seriesKey]lastSeen, sem HLL — budgets típicos (~10k séries)
//     cabem em <1MB por host (Assumption A4 do RESEARCH).
//   - GC lazy: quando o budget aperta, varre o hostMap e remove entries com
//     lastSeen anterior à janela (24h). Sem goroutine separada, sem timer.
//   - Fast-path para meta-métricas (`ispwatch.tagger.*` e `ispwatch.check.*`)
//     evita drop-loop recursivo (Pitfall 4 do RESEARCH).
package checks

import (
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	// defaultTaggerBudget é o fallback aplicado quando NewTagger recebe
	// budget <= 0 (proto CollectorConfig.tagger_budget_per_host == 0). 10k
	// séries cabem em <1MB de RAM por host (Assumption A4 do RESEARCH).
	defaultTaggerBudget = 10000

	// taggerSlidingWindow é a janela após a qual uma série não-vista é
	// considerada stale e elegível para purga no GC lazy.
	taggerSlidingWindow = 24 * time.Hour

	// metaMetricPrefixTagger e metaMetricPrefixCheck são prefixos que o
	// Filter deixa passar sempre, bypassando o budget. Pitfall 4: se a
	// própria meta-métrica de drop fosse sujeita ao budget, ela seria
	// dropada quando o budget estourasse e o operador perderia o sinal.
	metaMetricPrefixTagger = "ispwatch.tagger."
	metaMetricPrefixCheck  = "ispwatch.check."
)

// Tagger enforça cardinality budget per-host como middleware do Runtime.emit.
// Threadsafe — instância única é compartilhada entre todas as goroutines de
// check via Runtime.tagger.
type Tagger struct {
	budget int
	log    *slog.Logger

	mu   sync.Mutex
	seen map[string]map[string]time.Time
}

// NewTagger constrói um Tagger pronto para uso. budget <= 0 cai no default
// (10k); log nil cai em slog.Default().
func NewTagger(budget int, log *slog.Logger) *Tagger {
	if budget <= 0 {
		budget = defaultTaggerBudget
	}
	if log == nil {
		log = slog.Default()
	}
	return &Tagger{
		budget: budget,
		log:    log.With("component", "tagger"),
		seen:   map[string]map[string]time.Time{},
	}
}

// Budget retorna o limite atual (após resolução de default).
func (t *Tagger) Budget() int {
	return t.budget
}

// Filter aplica o budget por host. Retorna duas slices:
//   - kept: métricas que passaram (até budget novas séries por host, mais
//     todas as séries já vistas e todas as meta-métricas fast-path).
//   - drops: meta-métricas ispwatch.tagger.dropped (uma por série excedente),
//     prontas para serem concatenadas a kept pelo caller (Runtime.emit).
//
// A separação dois-returns facilita testes (sem injetar canal) e dá ao
// caller liberdade pra decidir o que fazer com os drops (geralmente append
// a kept antes do select no out channel).
func (t *Tagger) Filter(in []*collectorv1.Metric) (kept, drops []*collectorv1.Metric) {
	if len(in) == 0 {
		return nil, nil
	}
	kept = make([]*collectorv1.Metric, 0, len(in))

	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, m := range in {
		name := m.GetMetricName()

		// Fast-path: meta-métricas sempre passam (Pitfall 4 — evita drop-loop).
		if strings.HasPrefix(name, metaMetricPrefixTagger) ||
			strings.HasPrefix(name, metaMetricPrefixCheck) {
			kept = append(kept, m)
			continue
		}

		host := m.GetHostId()
		key := seriesKey(m)

		hostMap, ok := t.seen[host]
		if !ok {
			hostMap = map[string]time.Time{}
			t.seen[host] = hostMap
		}

		// Série já vista: atualiza lastSeen e admite.
		if _, exists := hostMap[key]; exists {
			hostMap[key] = now
			kept = append(kept, m)
			continue
		}

		// Série nova mas budget cheio: GC lazy para liberar slots stale.
		if len(hostMap) >= t.budget {
			t.gcLocked(hostMap, now)
		}

		// Ainda cheio depois do GC: drop + meta-métrica + log estruturado.
		if len(hostMap) >= t.budget {
			drops = append(drops, t.makeDropMetric(host, name, now))
			t.log.Warn("tagger drop",
				"host_id", host,
				"metric", name,
				"current_cardinality", len(hostMap),
				"budget", t.budget,
			)
			continue
		}

		// Há espaço: registra e admite.
		hostMap[key] = now
		kept = append(kept, m)
	}

	return kept, drops
}

// gcLocked purga entradas com lastSeen anterior à janela. Caller já segura t.mu.
func (t *Tagger) gcLocked(hostMap map[string]time.Time, now time.Time) {
	cutoff := now.Add(-taggerSlidingWindow)
	for k, ts := range hostMap {
		if ts.Before(cutoff) {
			delete(hostMap, k)
		}
	}
}

// makeDropMetric monta a meta-métrica ispwatch.tagger.dropped{host,metric}
// que será enviada junto com o batch ao backend para alerta.
func (t *Tagger) makeDropMetric(hostID, metricName string, now time.Time) *collectorv1.Metric {
	return &collectorv1.Metric{
		Time:       timestamppb.New(now),
		HostId:     hostID,
		MetricName: "ispwatch.tagger.dropped",
		Value:      1.0,
		Tags: map[string]string{
			"host":   hostID,
			"metric": metricName,
		},
		Source: "tagger",
	}
}

// seriesKey deriva uma chave determinística da métrica, agrupando por
// metric_name + tags ordenadas. host_id NÃO entra na key porque já é a
// dimensão do mapa externo (map[hostID]map[seriesKey]).
//
// Implementação simples: concat com separadores controlados. Não é hash
// criptográfico — strings cruas bastam para budgets <100k e evitam o risco
// de colisão silenciosa de hash curtos.
func seriesKey(m *collectorv1.Metric) string {
	tags := m.GetTags()
	if len(tags) == 0 {
		return m.GetMetricName()
	}
	pairs := make([]string, 0, len(tags))
	for k, v := range tags {
		// Pula chaves que duplicam dimensões já carregadas pelo Metric
		// (host_id é o hostID externo; tenant não está na key por design).
		if k == "host" || k == "host_id" {
			continue
		}
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return m.GetMetricName() + "|" + strings.Join(pairs, ",")
}
