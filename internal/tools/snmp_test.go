package tools

import (
	"testing"
	"time"
)

func TestIndexBelow(t *testing.T) {
	cases := []struct {
		oid, root, want string
	}{
		{"1.3.6.1.2.1.2.2.1.10.3", "1.3.6.1.2.1.2.2.1.10", "3"},
		{"1.3.6.1.2.1.2.2.1.10.1.5", "1.3.6.1.2.1.2.2.1.10", "1.5"},
		{"1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.10", ""},
		{"1.3.6.1.2.1.999.0", "1.3.6.1.2.1.2", ""},
	}
	for _, tc := range cases {
		t.Run(tc.oid, func(t *testing.T) {
			if got := indexBelow(tc.oid, tc.root); got != tc.want {
				t.Errorf("indexBelow(%q,%q)=%q want %q", tc.oid, tc.root, got, tc.want)
			}
		})
	}
}

func TestRequireStringSlice(t *testing.T) {
	good := map[string]any{"oids": []any{"1.3.6.1", "1.3.6.2"}}
	got, err := requireStringSlice(good, "oids")
	if err != nil || len(got) != 2 || got[0] != "1.3.6.1" {
		t.Errorf("good case failed: got=%v err=%v", got, err)
	}
	bad := []map[string]any{
		{},
		{"oids": "not array"},
		{"oids": []any{}},
		{"oids": []any{1, 2}},
		{"oids": []any{"", ""}},
	}
	for i, args := range bad {
		if _, err := requireStringSlice(args, "oids"); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestParamsFromArgs_V2cDefault(t *testing.T) {
	args := map[string]any{
		"target":          "10.0.0.1",
		"community":       "public",
		"timeout_seconds": 7,
	}
	p, err := paramsFromArgs(args)
	if err != nil {
		t.Fatalf("paramsFromArgs: %v", err)
	}
	if p.Target != "10.0.0.1" {
		t.Errorf("Target=%q", p.Target)
	}
	if p.Version != "v2c" {
		t.Errorf("Version=%q want v2c", p.Version)
	}
	if p.Community != "public" {
		t.Errorf("Community=%q", p.Community)
	}
	if p.Timeout != 7*time.Second {
		t.Errorf("Timeout=%v want 7s", p.Timeout)
	}
}

func TestParamsFromArgs_V2cExplicit(t *testing.T) {
	args := map[string]any{
		"target":    "router-a",
		"community": "ro",
		"version":   "v2c",
	}
	p, err := paramsFromArgs(args)
	if err != nil {
		t.Fatalf("paramsFromArgs: %v", err)
	}
	if p.Version != "v2c" || p.Community != "ro" {
		t.Errorf("unexpected: %+v", p)
	}
}

func TestParamsFromArgs_V3Full(t *testing.T) {
	args := map[string]any{
		"target":        "10.0.0.1",
		"version":       "v3",
		"v3_user":       "monitoring",
		"v3_auth_proto": "SHA256",
		"v3_auth_pass":  "auth-secret",
		"v3_priv_proto": "AES256",
		"v3_priv_pass":  "priv-secret",
		"v3_context":    "vrf-default",
	}
	p, err := paramsFromArgs(args)
	if err != nil {
		t.Fatalf("paramsFromArgs v3: %v", err)
	}
	if p.Version != "v3" {
		t.Errorf("Version=%q want v3", p.Version)
	}
	if p.V3User != "monitoring" {
		t.Errorf("V3User=%q", p.V3User)
	}
	if p.V3AuthProto != "SHA256" || p.V3PrivProto != "AES256" {
		t.Errorf("auth/priv proto wrong: %+v", p)
	}
	if p.V3AuthPass != "auth-secret" || p.V3PrivPass != "priv-secret" {
		t.Errorf("passwords mismatch: %+v", p)
	}
	if p.V3ContextName != "vrf-default" {
		t.Errorf("ContextName=%q", p.V3ContextName)
	}
	if p.Community != "" {
		t.Errorf("Community should be empty in v3, got %q", p.Community)
	}
}

func TestParamsFromArgs_V3MinimalNoAuthNoPriv(t *testing.T) {
	args := map[string]any{
		"target":  "10.0.0.1",
		"version": "v3",
		"v3_user": "u",
	}
	p, err := paramsFromArgs(args)
	if err != nil {
		t.Fatalf("paramsFromArgs: %v", err)
	}
	if p.V3AuthProto != "NoAuth" || p.V3PrivProto != "NoPriv" {
		t.Errorf("defaults wrong: %+v", p)
	}
}

func TestParamsFromArgs_V3MissingUser(t *testing.T) {
	args := map[string]any{"target": "10.0.0.1", "version": "v3"}
	if _, err := paramsFromArgs(args); err == nil {
		t.Fatalf("expected error: v3 sem v3_user deve falhar")
	}
}

func TestParamsFromArgs_V2cMissingCommunity(t *testing.T) {
	args := map[string]any{"target": "10.0.0.1"}
	if _, err := paramsFromArgs(args); err == nil {
		t.Fatalf("expected error: v2c sem community deve falhar")
	}
}

func TestParamsFromArgs_MissingTarget(t *testing.T) {
	args := map[string]any{"community": "x"}
	if _, err := paramsFromArgs(args); err == nil {
		t.Fatalf("expected error: target obrigatorio")
	}
}

func TestParamsFromArgs_InvalidVersion(t *testing.T) {
	args := map[string]any{"target": "x", "version": "v9", "community": "y"}
	if _, err := paramsFromArgs(args); err == nil {
		t.Fatalf("expected error: version invalida")
	}
}

func TestParamsFromArgs_DefaultTimeout(t *testing.T) {
	args := map[string]any{"target": "x", "community": "y"}
	p, err := paramsFromArgs(args)
	if err != nil {
		t.Fatalf("paramsFromArgs: %v", err)
	}
	if p.Timeout != defaultSnmpTimeout {
		t.Errorf("Timeout=%v want %v default", p.Timeout, defaultSnmpTimeout)
	}
}

// TestSnmpGet_ArgsValidation cobre os erros que SnmpGet.Execute retorna antes
// de tentar abrir socket UDP. Garante que o shape de validacao nao regrediu.
func TestSnmpGet_ArgsValidation(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing target", map[string]any{"community": "x", "oids": []any{"1.3"}}},
		{"missing community v2c", map[string]any{"target": "x", "oids": []any{"1.3"}}},
		{"missing oids", map[string]any{"target": "x", "community": "y"}},
		{"empty oids", map[string]any{"target": "x", "community": "y", "oids": []any{}}},
	}
	exec := SnmpGet{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.Execute(nil, tc.args); err == nil {
				t.Fatalf("esperava erro de validacao")
			}
		})
	}
}

// TestSnmpWalk_ArgsValidation cobre os erros que SnmpWalk.Execute retorna antes
// de tentar abrir socket UDP.
func TestSnmpWalk_ArgsValidation(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing target", map[string]any{"community": "x", "root": "1.3"}},
		{"missing community v2c", map[string]any{"target": "x", "root": "1.3"}},
		{"missing root", map[string]any{"target": "x", "community": "y"}},
	}
	exec := SnmpWalk{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.Execute(nil, tc.args); err == nil {
				t.Fatalf("esperava erro de validacao")
			}
		})
	}
}
