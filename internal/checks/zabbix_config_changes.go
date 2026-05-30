// zabbix_config_changes.go — aplica mudanças propostas pela UI no
// zabbix_server.conf real do host. Roda no mesmo tick que o config-ship,
// imediatamente depois — assim mudanças aplicadas já refletem no ship
// seguinte (sha256 muda → backend deduplica).
//
// Para cada change pending:
//   1. Lê arquivo atual
//   2. Aplica patches key-by-key via regex line-based
//   3. Valida sintaxe rodando `zabbix_server -T -c <tmp>` (best-effort)
//   4. Move atômico (tmp+rename)
//   5. Roda `zabbix_server -R config_cache_reload` (best-effort)
//   6. POST result com new_content
//
// Idempotência: se algum patch alvo da key já tá com o valor desejado,
// no-op pra essa linha. Patches malformados são reportados sem aplicar.
//
// Privilégios: assume agent rodando como root (típico em instalação
// systemd). Se não for root, write/exec vão falhar e o ciclo reporta
// `failed` com mensagem clara.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type pendingChange struct {
	ID       string      `json:"id"`
	Filename string      `json:"filename"`
	Patches  []confPatch `json:"patches"`
}

type confPatch struct {
	Key   string `json:"key"`
	Op    string `json:"op"` // "set" | "unset"
	Value string `json:"value"`
}

type changeResult struct {
	Status     string `json:"status"` // applied | failed
	Message    string `json:"message"`
	NewContent string `json:"new_content,omitempty"`
}

// applyPendingChanges puxa pending changes do backend e processa em loop.
// Erros isolam a change (não derrubam o ciclo). Métricas/logs por change.
func (c *zabbixSyncCheck) applyPendingChanges(ctx context.Context) {
	pendings, err := c.fetchPendingChanges(ctx)
	if err != nil {
		c.log.Debug("zabbix.sync fetch changes failed", "err", err)
		return
	}
	if len(pendings) == 0 {
		return
	}
	c.log.Info("zabbix.sync processing config changes", "count", len(pendings))
	for _, p := range pendings {
		c.applyOneChange(ctx, p)
	}
}

func (c *zabbixSyncCheck) fetchPendingChanges(ctx context.Context) ([]pendingChange, error) {
	q := url.Values{}
	q.Set("monitor_id", c.monitorID)
	body, err := getJSON(ctx, "/api/collector/v1/zabbix/config-changes?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var out []pendingChange
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse pending changes: %w", err)
	}
	return out, nil
}

func (c *zabbixSyncCheck) applyOneChange(ctx context.Context, ch pendingChange) {
	log := c.log.With("change_id", ch.ID, "filename", ch.Filename)
	log.Info("applying change", "patches", len(ch.Patches))

	original, err := os.ReadFile(ch.Filename)
	if err != nil {
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: fmt.Sprintf("read %s: %v", ch.Filename, err)})
		return
	}

	patched, applied, errs := applyPatches(string(original), ch.Patches)
	if len(errs) > 0 {
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: fmt.Sprintf("patch errors: %s", strings.Join(errs, "; "))})
		return
	}
	if applied == 0 {
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: "no patches applied (all no-op or unknown keys)"})
		return
	}

	// Best-effort validate via `zabbix_server -T -c <tmp>` quando existir.
	// Skip silencioso quando o binário não está no PATH (cenário Docker
	// agent host ≠ Zabbix container).
	tmp, err := os.CreateTemp(filepath.Dir(ch.Filename), ".ispwatch-conf-")
	if err != nil {
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: fmt.Sprintf("tmp create: %v", err)})
		return
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.WriteString(patched); err != nil {
		_ = tmp.Close()
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: fmt.Sprintf("tmp write: %v", err)})
		return
	}
	_ = tmp.Close()
	// preserve owner/mode of original
	origStat, _ := os.Stat(ch.Filename)
	if origStat != nil {
		_ = os.Chmod(tmpPath, origStat.Mode())
	}

	if zsrv, _ := exec.LookPath("zabbix_server"); zsrv != "" {
		out, err := exec.CommandContext(ctx, zsrv, "-T", "-c", tmpPath).CombinedOutput()
		if err != nil {
			c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
				Message: fmt.Sprintf("validation failed: %v — %s", err, truncateString(string(out), 200))})
			return
		}
	}

	// Move atômico.
	if err := os.Rename(tmpPath, ch.Filename); err != nil {
		c.reportChange(ctx, ch.ID, changeResult{Status: "failed",
			Message: fmt.Sprintf("rename: %v", err)})
		return
	}

	// Trigger reload (best-effort).
	reloadMsg := "reload skipped (zabbix_server not in PATH)"
	if zsrv, _ := exec.LookPath("zabbix_server"); zsrv != "" {
		out, err := exec.CommandContext(ctx, zsrv, "-R", "config_cache_reload").CombinedOutput()
		if err != nil {
			reloadMsg = fmt.Sprintf("reload failed: %v — %s", err, truncateString(string(out), 200))
			log.Warn("config_cache_reload failed", "err", err)
		} else {
			reloadMsg = "reload ok"
		}
	}

	c.reportChange(ctx, ch.ID, changeResult{
		Status:     "applied",
		Message:    fmt.Sprintf("%d/%d patches applied · %s", applied, len(ch.Patches), reloadMsg),
		NewContent: patched,
	})
	log.Info("change applied", "patches_applied", applied, "reload", reloadMsg)
}

func (c *zabbixSyncCheck) reportChange(ctx context.Context, id string, res changeResult) {
	path := "/api/collector/v1/zabbix/config-changes/" + url.PathEscape(id) + "/result"
	_, err := PostJSON(ctx, path, res)
	if err != nil {
		c.log.Warn("report change result failed", "change_id", id, "err", err)
	}
}

// applyPatches: para cada patch tenta atualizar a linha ativa com regex
// `^Key\s*=`. Se não achar linha ativa mas existe linha comentada `# Key=`
// faz uncomment+replace. Se não achar nenhuma, append no fim.
// Para op="unset", comenta a linha ativa.
func applyPatches(content string, patches []confPatch) (string, int, []string) {
	lines := strings.Split(content, "\n")
	var errs []string
	applied := 0

	for _, p := range patches {
		if p.Key == "" {
			errs = append(errs, "patch missing key")
			continue
		}
		activeRe := regexp.MustCompile("(?m)^([A-Za-z][A-Za-z0-9_]*)\\s*=\\s*.*$")
		commentedRe := regexp.MustCompile("(?m)^#\\s*([A-Za-z][A-Za-z0-9_]*)\\s*=\\s*.*$")

		switch p.Op {
		case "set":
			updated := false
			// 1) tenta substituir linha ativa
			for i, l := range lines {
				m := activeRe.FindStringSubmatch(l)
				if m != nil && strings.EqualFold(m[1], p.Key) {
					newLine := p.Key + "=" + p.Value
					if l == newLine {
						updated = true // no-op idempotent
					} else {
						lines[i] = newLine
						updated = true
						applied++
					}
					break
				}
			}
			// 2) tenta uncomment + replace na default
			if !updated {
				for i, l := range lines {
					m := commentedRe.FindStringSubmatch(l)
					if m != nil && strings.EqualFold(m[1], p.Key) {
						lines[i] = p.Key + "=" + p.Value
						updated = true
						applied++
						break
					}
				}
			}
			// 3) append no fim
			if !updated {
				lines = append(lines, p.Key+"="+p.Value)
				applied++
			}
		case "unset":
			updated := false
			for i, l := range lines {
				m := activeRe.FindStringSubmatch(l)
				if m != nil && strings.EqualFold(m[1], p.Key) {
					lines[i] = "# " + l + "  ## unset by ispwatch"
					updated = true
					applied++
					break
				}
			}
			if !updated {
				// Já estava unset → no-op
			}
		default:
			errs = append(errs, fmt.Sprintf("unknown op %q for key %s", p.Op, p.Key))
		}
	}
	return strings.Join(lines, "\n"), applied, errs
}

// getJSON é o helper simétrico ao PostJSON em backend_mtls.go — emite GET
// no endpoint usando o mesmo cert mTLS + tenant/collector query params.
func getJSON(ctx context.Context, path string) ([]byte, error) {
	return PostJSONOrGet(ctx, "GET", path, nil)
}
