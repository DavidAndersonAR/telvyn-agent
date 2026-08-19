// Package jobpull consumes short-lived device automation jobs over authenticated HTTP.
package jobpull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ispwatch/collector/internal/tools"
)

type Config struct {
	Endpoint     string
	TenantID     string
	CollectorID  string
	PollInterval time.Duration
	HTTPClient   *http.Client
	Logger       *slog.Logger
}

type pullResponse struct {
	Jobs []job `json:"jobs"`
}

type job struct {
	ID             string `json:"id"`
	Attempt        int    `json:"attempt"`
	Host           string `json:"host"`
	Vendor         string `json:"vendor"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SecretKind     string `json:"secret_kind"`
	Secret         string `json:"secret"`
	KnownHost      string `json:"known_host"`
	TestOnly       bool   `json:"test_only"`
}

// Run polls one job at a time. A result remains in memory and is retried until acknowledged.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Endpoint == "" || cfg.TenantID == "" || cfg.CollectorID == "" || cfg.HTTPClient == nil {
		return fmt.Errorf("jobpull: incomplete config")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "jobpull")

	var pending *completed
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		if pending != nil {
			if err := postResult(ctx, cfg, *pending); err != nil {
				log.Warn("result not acknowledged; will retry", "job_id", pending.id, "err", err)
			} else {
				pending = nil
			}
		} else {
			j, err := pullOnce(ctx, cfg)
			if err != nil {
				log.Warn("job pull failed", "err", err)
			} else if j != nil {
				result := execute(ctx, *j)
				pending = &completed{id: j.ID, result: result}
				if err := postResult(ctx, cfg, *pending); err == nil {
					pending = nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func pullOnce(ctx context.Context, cfg Config) (*job, error) {
	u := fmt.Sprintf("%s/api/collector/v1/jobs?tenant_id=%s&collector_id=%s",
		cfg.Endpoint, url.QueryEscape(cfg.TenantID), url.QueryEscape(cfg.CollectorID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	var out pullResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if len(out.Jobs) == 0 {
		return nil, nil
	}
	return &out.Jobs[0], nil
}

func execute(ctx context.Context, j job) map[string]any {
	if !j.TestOnly {
		if err := tools.ValidateReadOnlySSHCommand(j.Vendor, j.Command); err != nil {
			return map[string]any{"success": false, "exit_code": -1, "error": err.Error()}
		}
	}
	args := map[string]any{
		"host": j.Host, "port": j.SSHPort, "user": j.SSHUser,
		"timeout": j.TimeoutSeconds,
	}
	if !j.TestOnly {
		args["command"] = j.Command
	}
	if j.KnownHost != "" {
		args["known_host"] = j.KnownHost
	}
	if j.SecretKind == "private_key" {
		args["private_key"] = j.Secret
	} else {
		args["password"] = j.Secret
	}
	var result map[string]any
	var err error
	if j.TestOnly {
		result, err = (tools.SSHExec{}).TestConnection(ctx, args)
	} else {
		result, err = (tools.SSHExec{}).Execute(ctx, args)
	}
	if err != nil {
		return map[string]any{"success": false, "exit_code": -1, "error": err.Error()}
	}
	if j.TestOnly {
		return result
	}
	exit, _ := result["exit_code"].(float64)
	errText, _ := result["error"].(string)
	result["success"] = exit == 0 && errText == ""
	return result
}

type completed struct {
	id     string
	result map[string]any
}

func postResult(ctx context.Context, cfg Config, done completed) error {
	body, err := json.Marshal(done.result)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/api/collector/v1/jobs/%s/result?tenant_id=%s&collector_id=%s",
		cfg.Endpoint, url.PathEscape(done.id), url.QueryEscape(cfg.TenantID), url.QueryEscape(cfg.CollectorID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, msg)
	}
	return nil
}
