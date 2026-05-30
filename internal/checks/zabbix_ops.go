// zabbix_ops.go — Worker que processa a fila zabbix_inventory_op. Análogo
// ao zabbix_migrate.go, mas pra CRUD de items/triggers (não para migração
// de versão do Zabbix server).
//
// Polling: invocado uma vez por tick do zabbix_sync. Pega no máximo UM op
// pendente por tick — operações CRUD são rápidas (tipicamente < 1s), mas
// queremos preservar a ordem de criação no caso de bursts.
//
// Fluxo:
//  1. GET /api/collector/v1/zabbix/operations?monitor_id=X
//     → backend devolve {op_id, op_type, target_zabbix_id, target_zabbix_hostid, payload}
//       e marca status='running' atomicamente. Sem op pendente: 204.
//  2. dispatchOp roda o JSON-RPC apropriado contra Zabbix.
//  3. POST /api/collector/v1/zabbix/operations/{op_id}/result
//     → backend grava status terminal + result + dispara re-sync.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ispwatch/collector/internal/zabbix"
)

// opDTO é o payload recebido do backend pra cada op pendente.
type opDTO struct {
	OpID               string                 `json:"op_id"`
	OpType             string                 `json:"op_type"`
	TargetZabbixID     string                 `json:"target_zabbix_id,omitempty"`
	TargetZabbixHostID string                 `json:"target_zabbix_hostid,omitempty"`
	Payload            map[string]interface{} `json:"payload"`
}

// opResult é o que reportamos de volta no POST /result.
type opResult struct {
	Status       string                 `json:"status"` // succeeded | failed
	Result       map[string]interface{} `json:"result,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
}

// fetchAndExecOneOp puxa o próximo op da fila e executa. Retorna
// (ranSomething, err). Sem op pendente → (false, nil).
func (c *zabbixSyncCheck) fetchAndExecOneOp(ctx context.Context, cli *zabbix.Client) (bool, error) {
	respBody, err := PostJSONOrGet(ctx, "GET",
		"/api/collector/v1/zabbix/operations?monitor_id="+c.monitorID, nil)
	if err != nil {
		return false, err
	}
	if len(respBody) == 0 {
		return false, nil
	}
	var op opDTO
	if err := json.Unmarshal(respBody, &op); err != nil {
		return false, fmt.Errorf("decode op: %w", err)
	}
	if op.OpID == "" {
		return false, nil
	}

	c.log.Info("zabbix inventory op picked up",
		"op_id", op.OpID, "type", op.OpType,
		"target", op.TargetZabbixID, "host", op.TargetZabbixHostID)

	res := c.dispatchOp(ctx, cli, &op)

	if _, err := PostJSON(ctx,
		"/api/collector/v1/zabbix/operations/"+op.OpID+"/result", res); err != nil {
		c.log.Warn("zabbix inventory op result post failed",
			"op_id", op.OpID, "status", res.Status, "err", err)
		return true, err
	}
	c.log.Info("zabbix inventory op done",
		"op_id", op.OpID, "status", res.Status, "err", res.ErrorMessage)
	return true, nil
}

// dispatchOp escolhe a função por op_type. Recupera de panic e devolve
// failed com mensagem clara.
func (c *zabbixSyncCheck) dispatchOp(ctx context.Context, cli *zabbix.Client, op *opDTO) (out opResult) {
	defer func() {
		if r := recover(); r != nil {
			out = opResult{Status: "failed",
				ErrorMessage: fmt.Sprintf("agent panic: %v", r)}
		}
	}()

	switch op.OpType {
	case "item.create":
		return c.opItemCreate(ctx, cli, op)
	case "item.update":
		return c.opItemUpdate(ctx, cli, op)
	case "item.delete":
		return c.opItemDelete(ctx, cli, op)
	case "item.clone":
		return c.opItemClone(ctx, cli, op)
	case "trigger.create":
		return c.opTriggerCreate(ctx, cli, op)
	case "trigger.update":
		return c.opTriggerUpdate(ctx, cli, op)
	case "trigger.delete":
		return c.opTriggerDelete(ctx, cli, op)
	case "trigger.clone":
		return c.opTriggerClone(ctx, cli, op)
	case "host.update":
		return c.opHostUpdate(ctx, cli, op)
	case "event.acknowledge":
		return c.opEventAcknowledge(ctx, cli, op)
	}
	return opResult{Status: "failed",
		ErrorMessage: "unknown op_type: " + op.OpType}
}

// ---- item ops ----

func (c *zabbixSyncCheck) opItemCreate(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	fields := map[string]any{}
	for k, v := range op.Payload {
		fields[k] = v
	}
	// Backend envia hostid no campo dedicado pra evitar acidente. Sobrescreve
	// o que vier no payload.
	if op.TargetZabbixHostID != "" {
		fields["hostid"] = op.TargetZabbixHostID
	}
	if _, ok := fields["hostid"]; !ok {
		return failedOp("item.create: hostid required (set target_zabbix_hostid)")
	}
	newID, err := cli.CreateItem(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"new_zabbix_id": newID}}
}

func (c *zabbixSyncCheck) opItemUpdate(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("item.update: target_zabbix_id required")
	}
	fields := map[string]any{"itemid": op.TargetZabbixID}
	for k, v := range op.Payload {
		fields[k] = v
	}
	id, err := cli.UpdateItem(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"itemid": id}}
}

func (c *zabbixSyncCheck) opItemDelete(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("item.delete: target_zabbix_id required")
	}
	ids, err := cli.DeleteItem(ctx, []string{op.TargetZabbixID})
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"deleted": ids}}
}

// opItemClone: copia campos do source itemid, aplica overrides, cria novo.
// Override comum: hostid (clona pra outro host), name, key_.
func (c *zabbixSyncCheck) opItemClone(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("item.clone: target_zabbix_id required (source itemid)")
	}
	src, err := cli.GetItemForClone(ctx, op.TargetZabbixID)
	if err != nil {
		return failedOp(err.Error())
	}
	fields := filterByAllowlist(src, itemCreateAllowlist)
	// Aplica overrides do payload (UI manda { hostid?, name?, key_? ... }).
	for k, v := range op.Payload {
		fields[k] = v
	}
	if op.TargetZabbixHostID != "" {
		fields["hostid"] = op.TargetZabbixHostID
	}
	if _, ok := fields["hostid"]; !ok {
		return failedOp("item.clone: hostid required (set target_zabbix_hostid or include in payload)")
	}
	newID, err := cli.CreateItem(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{
			"new_zabbix_id":   newID,
			"cloned_from":     op.TargetZabbixID,
		}}
}

// ---- trigger ops ----

func (c *zabbixSyncCheck) opTriggerCreate(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	fields := map[string]any{}
	for k, v := range op.Payload {
		fields[k] = v
	}
	newID, err := cli.CreateTrigger(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"new_zabbix_id": newID}}
}

func (c *zabbixSyncCheck) opTriggerUpdate(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("trigger.update: target_zabbix_id required")
	}
	fields := map[string]any{"triggerid": op.TargetZabbixID}
	for k, v := range op.Payload {
		fields[k] = v
	}
	id, err := cli.UpdateTrigger(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"triggerid": id}}
}

func (c *zabbixSyncCheck) opTriggerDelete(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("trigger.delete: target_zabbix_id required")
	}
	ids, err := cli.DeleteTrigger(ctx, []string{op.TargetZabbixID})
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"deleted": ids}}
}

// ---- event ops ----

// opEventAcknowledge invoca event.acknowledge no Zabbix.
// Payload esperado:
//   { "action": 6, "message": "investigando" }  // action é bitmask Zabbix:
//      1=close, 2=ack, 4=add message, 8=change severity, 16=unack, 32=suppress
//   Default quando não passado: action=2 (ack) + 4 (add message) = 6.
// target_zabbix_id é o eventid.
func (c *zabbixSyncCheck) opEventAcknowledge(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("event.acknowledge: target_zabbix_id required (eventid)")
	}
	params := map[string]any{"eventids": op.TargetZabbixID}
	if a, ok := op.Payload["action"]; ok {
		params["action"] = a
	} else {
		params["action"] = 6 // ack + add message
	}
	if m, ok := op.Payload["message"].(string); ok && m != "" {
		params["message"] = m
	}
	raw, err := cli.RawCall(ctx, "event.acknowledge", params)
	if err != nil {
		return failedOp("event.acknowledge: " + err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"raw": json.RawMessage(raw)}}
}

// ---- host ops ----

// opHostUpdate aplica mudanças no host (nome, status, descrição, interface,
// grupos, templates, tags, macros). Backend monta o payload no formato
// Zabbix JSON-RPC; agent só repassa.
//
// Payload esperado:
//   {
//     "name": "Servidor X",
//     "host": "srv-x",
//     "description": "...",
//     "status": 0,
//     "interface": { type, ip, dns, port, useip, snmp: { version, community } },
//     "hostgroups": ["Linux servers", "Edge"],            // nomes
//     "templates":  ["Template OS Linux by Zabbix agent"], // nomes
//     "tags":       [{ "tag": "env", "value": "prod" }],
//     "macros":     [{ "macro": "{$X}", "value": "y" }]
//   }
//
// target_zabbix_id é o hostid do Zabbix.
func (c *zabbixSyncCheck) opHostUpdate(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("host.update: target_zabbix_id required")
	}
	fields := map[string]any{"hostid": op.TargetZabbixID}

	// Campos simples — copia 1:1.
	for _, k := range []string{"name", "host", "description"} {
		if v, ok := op.Payload[k]; ok {
			fields[k] = v
		}
	}
	if v, ok := op.Payload["status"]; ok {
		fields["status"] = v
	}

	// Interface — host.update SUBSTITUI o array `interfaces` inteiro, e Zabbix
	// recusa apagar interface que tenha itens vinculados. Pra atualizar in-place,
	// buscamos o interfaceid da main interface existente e o reaproveitamos no
	// payload, fazendo Zabbix tratar como update da mesma interface.
	if iface, ok := op.Payload["interface"].(map[string]any); ok && len(iface) > 0 {
		zi := map[string]any{
			"type":  iface["type"],
			"ip":    iface["ip"],
			"dns":   iface["dns"],
			"port":  iface["port"],
			"useip": iface["useip"],
			"main":  1,
		}
		existing, err := cli.GetHostsDetails(ctx, []string{op.TargetZabbixID})
		if err == nil && len(existing) > 0 {
			for _, ex := range existing[0].Interfaces {
				if ex["main"] == float64(1) || ex["main"] == "1" {
					if id, _ := ex["interfaceid"].(string); id != "" {
						zi["interfaceid"] = id
					}
					break
				}
			}
		}
		// SNMP interface (type=2) precisa de `details` em Zabbix 5.0+.
		if t, _ := iface["type"].(float64); int(t) == 2 {
			if snmp, ok := op.Payload["snmp"].(map[string]any); ok {
				zi["details"] = map[string]any{
					"version":   snmp["version"],
					"community": snmp["community"],
					"bulk":      1,
				}
			}
		}
		fields["interfaces"] = []map[string]any{zi}
	}

	// Grupos/templates: backend manda nomes (string[]); precisamos resolver
	// pra IDs antes do host.update. Fazemos hostgroup.get/template.get.
	if names, ok := op.Payload["hostgroups"].([]any); ok && len(names) > 0 {
		ids, err := resolveByName(ctx, cli, "hostgroup.get", "groupid", names)
		if err != nil {
			return failedOp("hostgroup resolve: " + err.Error())
		}
		fields["groups"] = ids
	}
	if names, ok := op.Payload["templates"].([]any); ok {
		// Pode ser lista vazia — Zabbix permite remover todos os templates.
		ids, err := resolveByName(ctx, cli, "template.get", "templateid", names)
		if err != nil {
			return failedOp("template resolve: " + err.Error())
		}
		fields["templates"] = ids
	}

	// Tags + macros são embed direto. Zabbix aceita array de objetos
	// {tag,value} e {macro,value}.
	if tags, ok := op.Payload["tags"].([]any); ok {
		fields["tags"] = tags
	}
	if macros, ok := op.Payload["macros"].([]any); ok {
		fields["macros"] = macros
	}

	newID, err := cli.UpdateHost(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{"hostid": newID}}
}

// resolveByName traduz nomes humanos pra IDs Zabbix via *.get com filter.
// Retorna lista de {idKey: "<id>"} pronta pra usar em host.update.
func resolveByName(ctx context.Context, cli *zabbix.Client, method, idKey string,
	names []any) ([]map[string]any, error) {
	if len(names) == 0 {
		return []map[string]any{}, nil
	}
	strs := make([]string, 0, len(names))
	for _, n := range names {
		if s, ok := n.(string); ok && s != "" {
			strs = append(strs, s)
		}
	}
	if len(strs) == 0 {
		return []map[string]any{}, nil
	}
	raw, err := cli.RawCall(ctx, method, map[string]any{
		"output":       []string{idKey, "name"},
		"filter":       map[string]any{"name": strs},
		"preservekeys": false,
	})
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if id, ok := r[idKey]; ok {
			out = append(out, map[string]any{idKey: id})
		}
	}
	return out, nil
}

func (c *zabbixSyncCheck) opTriggerClone(ctx context.Context, cli *zabbix.Client, op *opDTO) opResult {
	if op.TargetZabbixID == "" {
		return failedOp("trigger.clone: target_zabbix_id required (source triggerid)")
	}
	src, err := cli.GetTriggerForClone(ctx, op.TargetZabbixID)
	if err != nil {
		return failedOp(err.Error())
	}
	fields := filterByAllowlist(src, triggerCreateAllowlist)
	for k, v := range op.Payload {
		fields[k] = v
	}
	newID, err := cli.CreateTrigger(ctx, fields)
	if err != nil {
		return failedOp(err.Error())
	}
	return opResult{Status: "succeeded",
		Result: map[string]interface{}{
			"new_zabbix_id": newID,
			"cloned_from":   op.TargetZabbixID,
		}}
}

// itemCreateAllowlist lista os campos que Zabbix item.create aceita.
// Construído a partir da doc oficial Zabbix 6.0/7.0 — campos não listados
// (incluindo enabled_lifetime, lifetime, evaltype, discover, master_itemid
// quando vindo de prototype, etc.) são silenciosamente recusados num clone.
var itemCreateAllowlist = map[string]struct{}{
	"hostid": {}, "interfaceid": {}, "name": {}, "key_": {}, "type": {},
	"value_type": {}, "delay": {}, "history": {}, "trends": {}, "status": {},
	"units": {}, "valuemapid": {}, "params": {}, "ipmi_sensor": {}, "snmp_oid": {},
	"logtimefmt": {}, "jmx_endpoint": {}, "authtype": {}, "username": {},
	"password": {}, "publickey": {}, "privatekey": {}, "description": {},
	"inventory_link": {}, "timeout": {}, "url": {}, "query_fields": {},
	"posts": {}, "status_codes": {}, "follow_redirects": {}, "post_type": {},
	"http_proxy": {}, "headers": {}, "retrieve_mode": {}, "request_method": {},
	"output_format": {}, "allow_traps": {}, "ssl_cert_file": {}, "ssl_key_file": {},
	"ssl_key_password": {}, "verify_peer": {}, "verify_host": {}, "trapper_hosts": {},
	"parameters": {}, "preprocessing": {}, "tags": {},
}

// triggerCreateAllowlist — campos aceitos por trigger.create.
var triggerCreateAllowlist = map[string]struct{}{
	"description": {}, "expression": {}, "comments": {}, "dependencies": {},
	"priority": {}, "status": {}, "tags": {}, "type": {}, "url": {},
	"manual_close": {}, "opdata": {}, "recovery_mode": {}, "recovery_expression": {},
	"correlation_mode": {}, "correlation_tag": {}, "event_name": {},
}

// filterByAllowlist devolve um novo map só com as chaves presentes em allow.
// Substitui stripUncloneable (denylist frágil — toda nova release do Zabbix
// pode adicionar campos read-only que vazariam).
func filterByAllowlist(src map[string]any, allow map[string]struct{}) map[string]any {
	out := make(map[string]any, len(allow))
	for k, v := range src {
		if _, ok := allow[k]; ok {
			out[k] = v
		}
	}
	return out
}

// stripUncloneable remove campos que não podem ir num create:
//   - identificadores próprios do source (itemid, triggerid, templateid)
//   - campos read-only de estado (state, value, error, lastvalue, lastclock, lastchange)
//
// Mantém todos os campos de configuração (name, key_, type, value_type,
// delay, expression, description, priority, units, history, trends, ...).
//
// Deprecated: prefira filterByAllowlist (allowlist por kind). Mantido só
// até remover últimos callers.
func stripUncloneable(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	skip := map[string]struct{}{
		"itemid":            {},
		"triggerid":         {},
		"templateid":        {},
		"state":             {},
		"value":             {},
		"error":             {},
		"lastvalue":         {},
		"lastclock":         {},
		"lastns":            {},
		"prevvalue":         {},
		"lastchange":        {},
		"flags":             {},
		// Campos que Zabbix retorna em item.get/trigger.get mas recusa em
		// item.create/trigger.create: pertencem ao runtime ou ao discovery
		// rule (LLD prototypes), nunca aceitos num create direto.
		"enabled_lifetime":  {},
		"disabled_lifetime": {},
		"discover":          {},
		"lifetime":          {},
		"lifetime_type":     {},
		"master_itemid":     {},
		"parent_itemid":     {},
		"hosts":             {},
	}
	for k, v := range src {
		if _, drop := skip[k]; drop {
			continue
		}
		// Drop variantes LLD-prototype: lifetime, enabled_lifetime,
		// enabled_lifetime_type, disabled_lifetime, lifetime_type — Zabbix
		// recusa qualquer um destes em item.create / trigger.create.
		if strings.Contains(k, "lifetime") {
			continue
		}
		out[k] = v
	}
	return out
}

func failedOp(msg string) opResult {
	return opResult{Status: "failed", ErrorMessage: msg}
}
