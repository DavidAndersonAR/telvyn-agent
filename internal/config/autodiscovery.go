package config

import "strings"

// AutodiscoveryCIDRs extrai a lista de CIDRs do CollectorConfig.AutodiscoveryCidrs
// (proto field 8, Phase 3 Plan 05) e devolve trimmed/deduped. Vazia significa
// "sem scan" — snmp.autodiscover check nao roda.
//
// Helper standalone (Config struct mantém-se CLI-only) — main.go usa quando
// for popular CheckConfig.params["cidrs"] manualmente em modo bootstrap.
// Em produção a wire é: backend Quarkus copia CollectorConfig.autodiscovery_cidrs
// para params["cidrs"] de cada CheckConfig do tipo snmp.autodiscover.
//
// Aceita lista nil ou vazia (proto3 zero-value) — retorna slice vazia.
func AutodiscoveryCIDRs(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
