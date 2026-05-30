package tools

import (
	"context"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestConfigReload_Happy(t *testing.T) {
	var got []*collectorv1.AdapterConfig
	exec := NewConfigReload(func(list []*collectorv1.AdapterConfig) { got = list }, nil, nil)

	res, err := exec.Execute(context.Background(), map[string]any{
		"adapters": []any{
			map[string]any{"kind": "snmp_poll", "params": map[string]any{"community": "public"}},
			map[string]any{"kind": "icmp_ping"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].Kind != "snmp_poll" || got[1].Kind != "icmp_ping" {
		t.Fatalf("callback got wrong adapters: %+v", got)
	}
	if got[0].Params == nil {
		t.Fatalf("snmp_poll params lost")
	}
	if v := got[0].Params.AsMap()["community"]; v != "public" {
		t.Fatalf("community param lost: %v", v)
	}
	if got[1].Params != nil {
		t.Fatalf("icmp_ping params should be nil when absent")
	}
	if r := res["adapters_reloaded"]; r != float64(2) {
		t.Fatalf("adapters_reloaded count: want 2, got %v", r)
	}
}

func TestConfigReload_EmptyList(t *testing.T) {
	called := false
	exec := NewConfigReload(func(list []*collectorv1.AdapterConfig) {
		called = true
		if len(list) != 0 {
			t.Errorf("expected empty list, got %d", len(list))
		}
	}, nil, nil)
	if _, err := exec.Execute(context.Background(), map[string]any{"adapters": []any{}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("callback was not invoked for empty list")
	}
}

func TestConfigReload_BadInputs(t *testing.T) {
	exec := NewConfigReload(func([]*collectorv1.AdapterConfig) {}, nil, nil)
	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing adapters", map[string]any{}},
		{"adapters not array", map[string]any{"adapters": "nope"}},
		{"item not object", map[string]any{"adapters": []any{"hi"}}},
		{"missing kind", map[string]any{"adapters": []any{map[string]any{"params": map[string]any{}}}}},
		{"empty kind", map[string]any{"adapters": []any{map[string]any{"kind": ""}}}},
		{"params not object", map[string]any{"adapters": []any{map[string]any{"kind": "x", "params": 7}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.Execute(context.Background(), tc.args); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestConfigReload_NoCallback(t *testing.T) {
	exec := NewConfigReload(nil, nil, nil)
	if _, err := exec.Execute(context.Background(), map[string]any{"adapters": []any{}}); err == nil {
		t.Fatal("expected error when callback not wired")
	}
}

// ----- Novos testes: checks hot-reload -----

func TestConfigReload_Checks_ParsesAndCallsCallback(t *testing.T) {
	var got []*collectorv1.CheckConfig
	reload := NewConfigReload(nil, nil, func(checks []*collectorv1.CheckConfig) {
		got = checks
	})
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_id":         "linux-sys-h1",
				"check_type":       "linux.system",
				"interval_seconds": float64(30),
				"host_id":          "host-1",
				"enabled":          true,
				"template_id":      "linux.generic",
				"params":           map[string]any{"mounts_filter": "ext4|xfs"},
				"static_tags":      map[string]any{"role": "web"},
			},
		},
	}
	out, err := reload.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 check, got %d", len(got))
	}
	if got[0].CheckType != "linux.system" {
		t.Errorf("type=%q", got[0].CheckType)
	}
	if got[0].CheckId != "linux-sys-h1" {
		t.Errorf("id=%q", got[0].CheckId)
	}
	if got[0].Interval.AsDuration() != 30*time.Second {
		t.Errorf("interval=%v", got[0].Interval.AsDuration())
	}
	if got[0].HostId != "host-1" {
		t.Errorf("host_id=%q", got[0].HostId)
	}
	if got[0].TemplateId != "linux.generic" {
		t.Errorf("template_id=%q", got[0].TemplateId)
	}
	if got[0].Params["mounts_filter"] != "ext4|xfs" {
		t.Errorf("params: %v", got[0].Params)
	}
	if got[0].StaticTags["role"] != "web" {
		t.Errorf("static_tags: %v", got[0].StaticTags)
	}
	if out["checks_reloaded"].(float64) != 1.0 {
		t.Errorf("out: %v", out)
	}
}

func TestConfigReload_Checks_MissingType_Error(t *testing.T) {
	reload := NewConfigReload(nil, nil, func(checks []*collectorv1.CheckConfig) {})
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_id": "no-type",
			},
		},
	}
	_, err := reload.Execute(context.Background(), args)
	if err == nil {
		t.Fatal("expected error for missing check_type")
	}
	want := "config.reload: checks[0].check_type must be non-empty string"
	if err.Error() != want {
		t.Errorf("error=%q, want %q", err.Error(), want)
	}
}

func TestConfigReload_Checks_IntervalSeconds_ConvertedToDuration(t *testing.T) {
	var got []*collectorv1.CheckConfig
	reload := NewConfigReload(nil, nil, func(checks []*collectorv1.CheckConfig) {
		got = checks
	})
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_type":       "linux.system",
				"interval_seconds": float64(30),
			},
		},
	}
	_, err := reload.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 check, got %d", len(got))
	}
	if got[0].Interval.AsDuration() != 30*time.Second {
		t.Errorf("interval=%v, want 30s", got[0].Interval.AsDuration())
	}
}

func TestConfigReload_Checks_Nil_Callback_Error(t *testing.T) {
	reload := NewConfigReload(nil, nil, nil)
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_type": "linux.system",
			},
		},
	}
	_, err := reload.Execute(context.Background(), args)
	if err == nil {
		t.Fatal("expected error when reloadChecks is nil")
	}
	want := "config.reload: agent has no checks runtime wired"
	if err.Error() != want {
		t.Errorf("error=%q, want %q", err.Error(), want)
	}
}

func TestConfigReload_BackwardCompat_OnlyAdapters_StillWorks(t *testing.T) {
	var gotAdapters []*collectorv1.AdapterConfig
	checksCalledCount := 0
	reload := NewConfigReload(
		func(a []*collectorv1.AdapterConfig) { gotAdapters = a },
		nil,
		func(c []*collectorv1.CheckConfig) { checksCalledCount++ },
	)
	args := map[string]any{
		"adapters": []any{
			map[string]any{"kind": "snmp_poll"},
		},
	}
	out, err := reload.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if len(gotAdapters) != 1 {
		t.Errorf("want 1 adapter, got %d", len(gotAdapters))
	}
	if checksCalledCount != 0 {
		t.Errorf("reloadChecks should NOT be called when no checks arg; called %d times", checksCalledCount)
	}
	if out["adapters_reloaded"].(float64) != 1.0 {
		t.Errorf("adapters_reloaded=%v", out["adapters_reloaded"])
	}
}

func TestConfigReload_StaticTagsParsedAsMap(t *testing.T) {
	var got []*collectorv1.CheckConfig
	reload := NewConfigReload(nil, nil, func(checks []*collectorv1.CheckConfig) {
		got = checks
	})
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_type":  "linux.system",
				"static_tags": map[string]any{"role": "postgres"},
			},
		},
	}
	_, err := reload.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 check, got %d", len(got))
	}
	if got[0].StaticTags["role"] != "postgres" {
		t.Errorf("static_tags[role]=%q, want postgres", got[0].StaticTags["role"])
	}
}

func TestConfigReload_TemplateIdParsed(t *testing.T) {
	var got []*collectorv1.CheckConfig
	reload := NewConfigReload(nil, nil, func(checks []*collectorv1.CheckConfig) {
		got = checks
	})
	args := map[string]any{
		"checks": []any{
			map[string]any{
				"check_type":  "linux.system",
				"template_id": "linux.generic",
			},
		},
	}
	_, err := reload.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 check, got %d", len(got))
	}
	if got[0].TemplateId != "linux.generic" {
		t.Errorf("template_id=%q, want linux.generic", got[0].TemplateId)
	}
}
