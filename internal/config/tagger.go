package config

// DefaultTaggerBudget é o limite per-host aplicado quando o servidor não
// envia `CollectorConfig.tagger_budget_per_host` (proto field 7). Mantido
// em sync com `internal/checks.defaultTaggerBudget`.
//
// Decisão LOCKED em 03-CONTEXT.md: o budget é per-HOST, não per-tenant —
// REQ-CHECK-06 literal foi reinterpretado nesta phase.
const DefaultTaggerBudget = 10000

// ResolveTaggerBudget aplica o fallback ao default quando o servidor envia
// 0 (proto3 zero-value) ou um número não-positivo. Helper standalone para
// que o main.go possa derivar o budget sem misturar com Config (CLI flags).
func ResolveTaggerBudget(serverBudget int32) int {
	if serverBudget <= 0 {
		return DefaultTaggerBudget
	}
	return int(serverBudget)
}
