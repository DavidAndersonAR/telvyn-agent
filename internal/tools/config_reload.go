package tools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// ConfigReload is the executor for tool="config.reload" — server-pushed
// hot-reload, per D-22. The server includes the new config inline in args
// so the agent does NOT need to re-Register or open a new RPC; it hands
// each list to the same runtime callbacks the periodic Register reply
// feeds (OnAdapters / OnScheduledJobs / OnChecks).
//
// args schema (all fields optional, but at least one required):
//
//	adapters       []object  list of {kind: string, params?: object}
//	scheduled_jobs []object  list of {job_id, tool, args?, interval_seconds,
//	                                  host_id?, enabled?}
//	checks         []object  list of {check_id?, check_type, interval_seconds?,
//	                                  host_id?, enabled?, template_id?,
//	                                  params?, static_tags?, tags?}
//
// Backward compat: pre-Plan-3 servers send only "adapters" or "scheduled_jobs"
// — the executor still works (checks absent → don't touch the checks runtime).
type ConfigReload struct {
	reloadAdapters func([]*collectorv1.AdapterConfig)
	reloadJobs     func([]*collectorv1.ScheduledJob)
	reloadChecks   func([]*collectorv1.CheckConfig) // Plan 3
}

// NewConfigReload binds the executor to the three runtime callbacks. Any
// can be nil if the agent build doesn't have that runtime wired (defensive;
// the production wiring sets all three after Plan 4).
func NewConfigReload(
	reloadAdapters func([]*collectorv1.AdapterConfig),
	reloadJobs func([]*collectorv1.ScheduledJob),
	reloadChecks func([]*collectorv1.CheckConfig),
) *ConfigReload {
	return &ConfigReload{
		reloadAdapters: reloadAdapters,
		reloadJobs:     reloadJobs,
		reloadChecks:   reloadChecks,
	}
}

func (c *ConfigReload) Name() string { return "config.reload" }

func (c *ConfigReload) Execute(_ context.Context, args map[string]any) (map[string]any, error) {
	gotAdapters := false
	gotJobs := false
	gotChecks := false
	out := map[string]any{}

	if rawList, ok := args["adapters"]; ok {
		gotAdapters = true
		if c.reloadAdapters == nil {
			return nil, errors.New("config.reload: agent has no adapter runtime wired")
		}
		configs, kinds, err := parseAdapters(rawList)
		if err != nil {
			return nil, err
		}
		c.reloadAdapters(configs)
		out["adapters_reloaded"] = float64(len(configs))
		out["adapter_kinds"] = asAnySlice(kinds)
	}

	if rawList, ok := args["scheduled_jobs"]; ok {
		gotJobs = true
		if c.reloadJobs == nil {
			return nil, errors.New("config.reload: agent has no scheduler runtime wired")
		}
		jobs, tools, err := parseScheduledJobs(rawList)
		if err != nil {
			return nil, err
		}
		c.reloadJobs(jobs)
		out["jobs_reloaded"] = float64(len(jobs))
		out["job_tools"] = asAnySlice(tools)
	}

	if rawList, ok := args["checks"]; ok {
		gotChecks = true
		if c.reloadChecks == nil {
			return nil, errors.New("config.reload: agent has no checks runtime wired")
		}
		checks, types, err := parseChecks(rawList)
		if err != nil {
			return nil, err
		}
		c.reloadChecks(checks)
		out["checks_reloaded"] = float64(len(checks))
		out["check_types"] = asAnySlice(types)
	}

	if !gotAdapters && !gotJobs && !gotChecks {
		return nil, errors.New("config.reload: at least one of \"adapters\", \"scheduled_jobs\", or \"checks\" required")
	}
	return out, nil
}

func parseAdapters(rawList any) ([]*collectorv1.AdapterConfig, []string, error) {
	items, ok := rawList.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("config.reload: arg \"adapters\" must be array, got %T", rawList)
	}
	configs := make([]*collectorv1.AdapterConfig, 0, len(items))
	kinds := make([]string, 0, len(items))
	for i, raw := range items {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("config.reload: adapters[%d] must be object, got %T", i, raw)
		}
		kindRaw, ok := entry["kind"]
		if !ok {
			return nil, nil, fmt.Errorf("config.reload: adapters[%d] missing \"kind\"", i)
		}
		kind, ok := kindRaw.(string)
		if !ok || kind == "" {
			return nil, nil, fmt.Errorf("config.reload: adapters[%d].kind must be non-empty string", i)
		}
		ac := &collectorv1.AdapterConfig{Kind: kind}
		if pv, hasParams := entry["params"]; hasParams {
			pm, ok := pv.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("config.reload: adapters[%d].params must be object, got %T", i, pv)
			}
			ps, err := structpb.NewStruct(pm)
			if err != nil {
				return nil, nil, fmt.Errorf("config.reload: adapters[%d].params not structpb-encodable: %w", i, err)
			}
			ac.Params = ps
		}
		configs = append(configs, ac)
		kinds = append(kinds, kind)
	}
	return configs, kinds, nil
}

func parseScheduledJobs(rawList any) ([]*collectorv1.ScheduledJob, []string, error) {
	items, ok := rawList.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("config.reload: arg \"scheduled_jobs\" must be array, got %T", rawList)
	}
	jobs := make([]*collectorv1.ScheduledJob, 0, len(items))
	tools := make([]string, 0, len(items))
	for i, raw := range items {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("config.reload: scheduled_jobs[%d] must be object, got %T", i, raw)
		}
		tool, ok := entry["tool"].(string)
		if !ok || tool == "" {
			return nil, nil, fmt.Errorf("config.reload: scheduled_jobs[%d].tool must be non-empty string", i)
		}
		j := &collectorv1.ScheduledJob{Tool: tool, Enabled: true}
		if v, ok := entry["job_id"].(string); ok {
			j.JobId = v
		}
		if v, ok := entry["host_id"].(string); ok {
			j.HostId = v
		}
		if v, ok := entry["enabled"].(bool); ok {
			j.Enabled = v
		}
		// interval_seconds comes off the wire as float64 (structpb).
		switch v := entry["interval_seconds"].(type) {
		case float64:
			j.IntervalSeconds = int32(v)
		case int:
			j.IntervalSeconds = int32(v)
		}
		if av, ok := entry["args"]; ok {
			am, ok := av.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("config.reload: scheduled_jobs[%d].args must be object, got %T", i, av)
			}
			as, err := structpb.NewStruct(am)
			if err != nil {
				return nil, nil, fmt.Errorf("config.reload: scheduled_jobs[%d].args not structpb-encodable: %w", i, err)
			}
			j.Args = as
		}
		jobs = append(jobs, j)
		tools = append(tools, tool)
	}
	return jobs, tools, nil
}

func parseChecks(rawList any) ([]*collectorv1.CheckConfig, []string, error) {
	items, ok := rawList.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("config.reload: arg \"checks\" must be array, got %T", rawList)
	}
	checks := make([]*collectorv1.CheckConfig, 0, len(items))
	types := make([]string, 0, len(items))
	for i, raw := range items {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("config.reload: checks[%d] must be object, got %T", i, raw)
		}
		ctype, ok := entry["check_type"].(string)
		if !ok || ctype == "" {
			return nil, nil, fmt.Errorf("config.reload: checks[%d].check_type must be non-empty string", i)
		}
		cc := &collectorv1.CheckConfig{CheckType: ctype, Enabled: true}
		if v, ok := entry["check_id"].(string); ok {
			cc.CheckId = v
		}
		if v, ok := entry["host_id"].(string); ok {
			cc.HostId = v
		}
		if v, ok := entry["enabled"].(bool); ok {
			cc.Enabled = v
		}
		if v, ok := entry["template_id"].(string); ok {
			cc.TemplateId = v
		}
		// interval_seconds (float64 via structpb) → Duration proto
		switch v := entry["interval_seconds"].(type) {
		case float64:
			cc.Interval = durationpb.New(time.Duration(v) * time.Second)
		case int:
			cc.Interval = durationpb.New(time.Duration(v) * time.Second)
		}
		// params map<string,string>
		if pv, ok := entry["params"].(map[string]any); ok {
			cc.Params = make(map[string]string, len(pv))
			for k, val := range pv {
				if sv, ok := val.(string); ok {
					cc.Params[k] = sv
				}
			}
		}
		// static_tags map<string,string>
		if pv, ok := entry["static_tags"].(map[string]any); ok {
			cc.StaticTags = make(map[string]string, len(pv))
			for k, val := range pv {
				if sv, ok := val.(string); ok {
					cc.StaticTags[k] = sv
				}
			}
		}
		// tags []string
		if tv, ok := entry["tags"].([]any); ok {
			for _, t := range tv {
				if ts, ok := t.(string); ok {
					cc.Tags = append(cc.Tags, ts)
				}
			}
		}
		checks = append(checks, cc)
		types = append(types, ctype)
	}
	return checks, types, nil
}

// asAnySlice converts []string to []any so structpb roundtrips it cleanly
// (structpb.NewStruct does NOT accept []string — must be []any of strings).
func asAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
