// Package obfuscate normaliza atributos sensíveis de spans ANTES da agregação
// e do envio: tira valores literais de SQL, remove query string de URLs e
// redige um conjunto básico de atributos com PII. Roda no hot path (Push),
// in-place antes do envio ao backend.
package obfuscate

import (
	"regexp"
	"strings"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Literais de string SQL ('...', com ” escapado) e números viram '?'.
var (
	sqlStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)
	sqlNumberLiteral = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
)

// urlAttrs e sqlAttrs cobrem as convenções OTLP novas e legadas.
var (
	urlAttrs = []string{"http.url", "http.target", "url.full", "url.path", "url.query"}
	sqlAttrs = []string{"db.statement", "db.query.text"}
	// piiAttrs são redigidos por completo (substituídos por "?").
	piiAttrs = []string{
		"http.request.header.authorization",
		"http.request.header.cookie",
		"db.user",
		"enduser.id",
	}
)

// Apply normaliza o span IN-PLACE. Seguro pra span nil / sem atributos.
func Apply(s *collectorv1.Span) {
	if s == nil || len(s.Attributes) == 0 {
		return
	}
	for _, k := range sqlAttrs {
		if v := s.Attributes[k]; v != "" {
			s.Attributes[k] = ObfuscateSQL(v)
		}
	}
	for _, k := range urlAttrs {
		if v := s.Attributes[k]; v != "" {
			s.Attributes[k] = StripQuery(v)
		}
	}
	for _, k := range piiAttrs {
		if _, ok := s.Attributes[k]; ok {
			s.Attributes[k] = "?"
		}
	}
}

// ObfuscateSQL troca literais de string e números por '?', preservando a forma
// da query (pro agrupamento por resource ter baixa cardinalidade).
func ObfuscateSQL(sql string) string {
	sql = sqlStringLiteral.ReplaceAllString(sql, "?")
	sql = sqlNumberLiteral.ReplaceAllString(sql, "?")
	return sql
}

// StripQuery remove a query string (tudo após o primeiro '?') de uma URL.
func StripQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
