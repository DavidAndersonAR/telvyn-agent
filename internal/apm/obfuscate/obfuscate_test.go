package obfuscate

import (
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestObfuscateSQL(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM users WHERE id = 42":                 "SELECT * FROM users WHERE id = ?",
		"SELECT * FROM t WHERE name = 'João' AND age = 30":  "SELECT * FROM t WHERE name = ? AND age = ?",
		"INSERT INTO x VALUES (1, 2.5, 'a')":                "INSERT INTO x VALUES (?, ?, ?)",
		"SELECT * FROM t WHERE s = 'O''Brien'":              "SELECT * FROM t WHERE s = ?",
	}
	for in, want := range cases {
		if got := ObfuscateSQL(in); got != want {
			t.Errorf("ObfuscateSQL(%q) = %q, queria %q", in, got, want)
		}
	}
}

func TestStripQuery(t *testing.T) {
	if got := StripQuery("https://api/x?token=abc&id=1"); got != "https://api/x" {
		t.Errorf("StripQuery = %q", got)
	}
	if got := StripQuery("/path/sem/query"); got != "/path/sem/query" {
		t.Errorf("StripQuery sem query mudou: %q", got)
	}
}

func TestApply(t *testing.T) {
	s := &collectorv1.Span{
		Attributes: map[string]string{
			"db.statement":                       "SELECT * FROM t WHERE id = 7",
			"http.url":                           "https://api/users?secret=xyz",
			"http.request.header.authorization":  "Bearer supersecret",
			"http.route":                         "/users/{id}",
		},
	}
	Apply(s)
	if s.Attributes["db.statement"] != "SELECT * FROM t WHERE id = ?" {
		t.Errorf("SQL não obfuscado: %q", s.Attributes["db.statement"])
	}
	if s.Attributes["http.url"] != "https://api/users" {
		t.Errorf("query não removida: %q", s.Attributes["http.url"])
	}
	if s.Attributes["http.request.header.authorization"] != "?" {
		t.Errorf("authorization não redigido: %q", s.Attributes["http.request.header.authorization"])
	}
	if s.Attributes["http.route"] != "/users/{id}" {
		t.Errorf("http.route não devia mudar: %q", s.Attributes["http.route"])
	}
}

func TestApply_NilSafe(t *testing.T) {
	Apply(nil)
	Apply(&collectorv1.Span{}) // sem atributos
}
