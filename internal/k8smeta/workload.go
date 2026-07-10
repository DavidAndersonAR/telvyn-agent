// Package k8smeta contém helpers de metadata do Kubernetes compartilhados
// entre os coletores (quarkus scraper, webhook de auto-injeção e, adiante, o
// cluster-agent). É o ponto ÚNICO da derivação pod→workload — antes duplicada
// idêntica em internal/quarkus e internal/webhook.
package k8smeta

import "strings"

// WorkloadOf deriva o nome do workload (Deployment/StatefulSet/DaemonSet) a
// partir do nome do pod. MESMA heurística do frontend (lib/workload.ts):
//
//	backend-7959f7697-z6psv → backend   (Deployment: -<rsHash>-<podHash>)
//	postgres-0              → postgres   (StatefulSet: -<ordinal>)
//
// Idempotente pra nomes que já são workload.
func WorkloadOf(pod string) string {
	if pod == "" {
		return pod
	}
	parts := strings.Split(pod, "-")
	if len(parts) < 2 {
		return pod
	}
	last := parts[len(parts)-1]
	if !isPodSuffix(last) && !isAllDigits(last) {
		return pod
	}
	end := len(parts) - 1
	if end >= 2 && isReplicaSetHash(parts[end-1]) {
		end--
	}
	return strings.Join(parts[:end], "-")
}

func isAlnumLower(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isPodSuffix(s string) bool { return len(s) == 5 && isAlnumLower(s) }

func isReplicaSetHash(s string) bool {
	if len(s) < 8 || len(s) > 10 || !isAlnumLower(s) {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
