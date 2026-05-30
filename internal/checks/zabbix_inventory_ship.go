// zabbix_inventory_ship.go — busca items/triggers/problems via JSON-RPC e
// envia pro backend. Read-only; escritas vão pela mTLS step queue na Fase 2.
//
// Cadência (controlada por zabbix_sync.go):
//   - items + triggers: a cada 5min (chamada item.get e trigger.get; payload
//     pode crescer pra 10MB+ em zabbix grandes — backend faz upsert por
//     (monitor_id, zabbix_id) com staleness via last_seen_at)
//   - problems: a cada 1min (problem.get; payload pequeno, freshness importa)
package checks

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ispwatch/collector/internal/zabbix"
)

// shipInventory chama item.get + trigger.get e posta no /api/collector/v1/zabbix/inventory.
func (c *zabbixSyncCheck) shipInventory(ctx context.Context, cli *zabbix.Client, hostIDs []string) error {
	if len(hostIDs) == 0 {
		return nil
	}
	items, err := cli.GetItemsFull(ctx, hostIDs)
	if err != nil {
		return fmt.Errorf("item.get: %w", err)
	}
	triggers, err := cli.GetTriggers(ctx, hostIDs)
	if err != nil {
		return fmt.Errorf("trigger.get: %w", err)
	}

	type itemDto struct {
		ItemID     string `json:"zabbix_itemid"`
		HostID     string `json:"zabbix_hostid"`
		Key        string `json:"key"`
		Name       string `json:"name"`
		Type       int    `json:"type"`
		ValueType  int    `json:"value_type"`
		Status     int    `json:"status"`
		State      int    `json:"state"`
		Delay      string `json:"delay,omitempty"`
		Units      string `json:"units,omitempty"`
		Error      string `json:"error,omitempty"`
		LastValue  string `json:"last_value,omitempty"`
		LastClock  int64  `json:"last_clock,omitempty"`
		TemplateID string `json:"template_id,omitempty"`
	}
	type triggerDto struct {
		TriggerID   string   `json:"zabbix_triggerid"`
		HostIDs     []string `json:"zabbix_hostids"`
		Description string   `json:"description"`
		Expression  string   `json:"expression"`
		Priority    int      `json:"priority"`
		Status      int      `json:"status"`
		State       int      `json:"state"`
		Value       int      `json:"value"`
		Error       string   `json:"error,omitempty"`
		LastChange  int64    `json:"last_change,omitempty"`
		TemplateID  string   `json:"template_id,omitempty"`
	}
	type payload struct {
		MonitorID string       `json:"monitor_id"`
		Items     []itemDto    `json:"items"`
		Triggers  []triggerDto `json:"triggers"`
	}

	pItems := make([]itemDto, 0, len(items))
	for _, it := range items {
		pItems = append(pItems, itemDto{
			ItemID:     it.ItemID,
			HostID:     it.HostID,
			Key:        it.Key,
			Name:       it.Name,
			Type:       atoi(it.Type),
			ValueType:  atoi(it.ValueType),
			Status:     atoi(it.Status),
			State:      atoi(it.State),
			Delay:      it.Delay,
			Units:      it.Units,
			Error:      it.Error,
			LastValue:  it.LastValue,
			LastClock:  atoi64(it.LastClock),
			TemplateID: it.TemplateID,
		})
	}
	pTriggers := make([]triggerDto, 0, len(triggers))
	for _, t := range triggers {
		pTriggers = append(pTriggers, triggerDto{
			TriggerID:   t.TriggerID,
			HostIDs:     t.HostIDs,
			Description: t.Description,
			Expression:  t.Expression,
			Priority:    atoi(t.Priority),
			Status:      atoi(t.Status),
			State:       atoi(t.State),
			Value:       atoi(t.Value),
			Error:       t.Error,
			LastChange:  atoi64(t.LastChange),
			TemplateID:  t.TemplateID,
		})
	}

	body, err := PostJSON(ctx, "/api/collector/v1/zabbix/inventory", payload{
		MonitorID: c.monitorID,
		Items:     pItems,
		Triggers:  pTriggers,
	})
	if err != nil {
		return fmt.Errorf("inventory POST: %w (body=%s)", err, truncateString(string(body), 200))
	}
	c.log.Info("zabbix.sync inventory shipped",
		"items", len(pItems), "triggers", len(pTriggers))
	return nil
}

// shipProblems posta os problemas ativos pro backend. Backend resolve quem
// sumiu (active no Zabbix mas não chegou aqui) marcando resolved=true.
func (c *zabbixSyncCheck) shipProblems(ctx context.Context, cli *zabbix.Client, hostIDs []string) error {
	probs, err := cli.GetProblems(ctx, hostIDs)
	if err != nil {
		return fmt.Errorf("problem.get: %w", err)
	}
	type problemDto struct {
		EventID      string   `json:"zabbix_eventid"`
		TriggerID    string   `json:"zabbix_triggerid"`
		HostIDs      []string `json:"zabbix_hostids"`
		Name         string   `json:"name"`
		Severity     int      `json:"severity"`
		Clock        int64    `json:"clock"`
		Acknowledged bool     `json:"acknowledged"`
	}
	type payload struct {
		MonitorID string       `json:"monitor_id"`
		Problems  []problemDto `json:"problems"`
	}

	out := make([]problemDto, 0, len(probs))
	for _, p := range probs {
		out = append(out, problemDto{
			EventID:      p.EventID,
			TriggerID:    p.TriggerID,
			HostIDs:      p.HostIDs,
			Name:         p.Name,
			Severity:     atoi(p.Severity),
			Clock:        atoi64(p.Clock),
			Acknowledged: p.Acknowledged == "1",
		})
	}

	body, err := PostJSON(ctx, "/api/collector/v1/zabbix/problems", payload{
		MonitorID: c.monitorID,
		Problems:  out,
	})
	if err != nil {
		return fmt.Errorf("problems POST: %w (body=%s)", err, truncateString(string(body), 200))
	}
	c.log.Info("zabbix.sync problems shipped", "count", len(out))
	return nil
}

// shipHostDetails busca host.get rico (interfaces, grupos, templates,
// tags, macros) e posta um JSON blob por host pro backend cachear. Usado
// pela tela de edição do host. Cadência igual ao shipInventory (5min).
func (c *zabbixSyncCheck) shipHostDetails(ctx context.Context, cli *zabbix.Client, hostIDs []string) error {
	if len(hostIDs) == 0 {
		return nil
	}
	details, err := cli.GetHostsDetails(ctx, hostIDs)
	if err != nil {
		return fmt.Errorf("host.get details: %w", err)
	}

	type hostDto struct {
		ZabbixHostID string                 `json:"zabbix_hostid"`
		Details      map[string]interface{} `json:"details"`
	}
	type payload struct {
		MonitorID string    `json:"monitor_id"`
		Hosts     []hostDto `json:"hosts"`
	}

	out := make([]hostDto, 0, len(details))
	for _, d := range details {
		// Reshape do JSON-RPC do Zabbix pro shape esperado pela UI
		// (ver comentário em V20260521050000__zabbix_host_detail.sql).
		shaped := map[string]interface{}{
			"visible_name": d.VisibleName,
			"hostname":     d.Hostname,
			"description":  d.Description,
			"status":       atoi(d.Status),
		}
		if len(d.Interfaces) > 0 {
			// Escolhe interface main=1; cai pra primeira disponível.
			var main map[string]any
			for _, ifc := range d.Interfaces {
				if asStr(ifc["main"]) == "1" {
					main = ifc
					break
				}
			}
			if main == nil {
				main = d.Interfaces[0]
			}
			shaped["interface"] = map[string]any{
				"type":  atoi(asStr(main["type"])),
				"ip":    asStr(main["ip"]),
				"dns":   asStr(main["dns"]),
				"port":  asStr(main["port"]),
				"useip": atoi(asStr(main["useip"])),
			}
			// SNMP details opcional (estrutura `details` em interfaces v5+ apenas).
			if det, ok := main["details"].(map[string]any); ok {
				shaped["snmp"] = map[string]any{
					"version":   asStr(det["version"]),
					"community": asStr(det["community"]),
				}
			}
		}
		shaped["hostgroups"] = pickMaps(d.Groups, "groupid", "name")
		shaped["templates"] = pickMaps(d.ParentTpls, "templateid", "name")
		shaped["tags"] = pickMaps(d.Tags, "tag", "value")
		shaped["macros"] = pickMaps(d.Macros, "macro", "value")
		out = append(out, hostDto{ZabbixHostID: d.HostID, Details: shaped})
	}

	body, err := PostJSON(ctx, "/api/collector/v1/zabbix/host-details", payload{
		MonitorID: c.monitorID,
		Hosts:     out,
	})
	if err != nil {
		return fmt.Errorf("host-details POST: %w (body=%s)", err, truncateString(string(body), 200))
	}
	c.log.Info("zabbix.sync host details shipped", "count", len(out))
	return nil
}

func asStr(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// pickMaps copia uma lista de objetos só com as chaves desejadas (mantém
// o JSON enxuto). Útil pra hostgroups/templates/tags/macros onde só
// usamos 2 campos cada.
func pickMaps(src []map[string]any, keys ...string) []map[string]any {
	out := make([]map[string]any, 0, len(src))
	for _, m := range src {
		row := make(map[string]any, len(keys))
		for _, k := range keys {
			if v, ok := m[k]; ok {
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return out
}

func atoi(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func atoi64(s string) int64 {
	if s == "" {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
