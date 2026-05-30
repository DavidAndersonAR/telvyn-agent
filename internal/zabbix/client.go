// Package zabbix implementa um cliente JSON-RPC mínimo da API do Zabbix
// (versão 5.0+; 7.0 testado). Cobre o que o check zabbix.sync precisa
// hoje: apiinfo.version (sanity), user.login (para auth USERNAME_PASSWORD)
// e host.get (com interfaces).
//
// Não usa libs externas — net/http + encoding/json suficientes. Token via
// header Authorization: Bearer (Zabbix 5.4+); fallback para "auth" no body
// é o caminho legado mas todos os métodos novos aceitam Bearer, então
// padronizamos nele.
package zabbix

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuthType reflete o que o backend nos envia via config-pull params.
type AuthType string

const (
	AuthAPIToken         AuthType = "API_TOKEN"
	AuthUsernamePassword AuthType = "USERNAME_PASSWORD"
)

// Client encapsula uma sessão contra um Zabbix server.
//
// Não é thread-safe: pretende-se uma instância por tick do check
// (createndo, consultando e descartando). Cheap o suficiente — não há
// connection-level state ao usar API_TOKEN.
type Client struct {
	baseURL    string // ex: http://10.0.5.99/zabbix → endpoint é baseURL + /api_jsonrpc.php
	apiToken   string // só usado se AuthType==AuthAPIToken (Bearer) OU se user.login retornou um session token
	authType   AuthType
	username   string
	password   string
	httpClient *http.Client
}

// New constrói um cliente. Se authType=USERNAME_PASSWORD, Login() precisa ser
// chamado antes de qualquer host.get/problem.get — ele troca user+password
// pelo session token via user.login, e o resto do código usa esse token.
func New(baseURL string, authType AuthType, username, password, apiToken string,
	validateTLS bool, timeout time.Duration) *Client {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !validateTLS},
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiToken:   apiToken,
		authType:   authType,
		username:   username,
		password:   password,
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
	}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      int    `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *rpcError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("zabbix rpc %d: %s — %s", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("zabbix rpc %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
	ID      int             `json:"id"`
}

// RawCall é o wrapper público pro JSON-RPC genérico. Usado por callers
// que precisam invocar métodos do Zabbix que ainda não têm um wrapper
// fortemente tipado (ex: hostgroup.get pra resolver nomes em IDs).
func (c *Client) RawCall(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return c.call(ctx, method, params, true)
}

// call executa um JSON-RPC contra o endpoint. needAuth=true injeta o Bearer
// se apiToken não estiver vazio.
func (c *Client) call(ctx context.Context, method string, params any, needAuth bool) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", Method: method, Params: params, ID: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("zabbix marshal request: %w", err)
	}

	url := c.baseURL + "/api_jsonrpc.php"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("zabbix new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	if needAuth && c.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zabbix http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("zabbix read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("zabbix http %d: %s", resp.StatusCode,
			truncate(string(respBody), 200))
	}

	var out rpcResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("zabbix unmarshal: %w (body=%s)",
			err, truncate(string(respBody), 200))
	}
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

// Version retorna a versão reportada pelo Zabbix (apiinfo.version). Não
// precisa de auth. Usado como sanity check antes do host.get.
func (c *Client) Version(ctx context.Context) (string, error) {
	raw, err := c.call(ctx, "apiinfo.version", struct{}{}, false)
	if err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("zabbix version unmarshal: %w", err)
	}
	return v, nil
}

// Login (USERNAME_PASSWORD apenas) troca user+pass pelo session token, que
// é gravado em apiToken para chamadas subsequentes. Pra AuthAPIToken vira
// no-op (o Bearer já está pronto).
func (c *Client) Login(ctx context.Context) error {
	if c.authType != AuthUsernamePassword {
		return nil
	}
	params := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	raw, err := c.call(ctx, "user.login", params, false)
	if err != nil {
		return fmt.Errorf("user.login: %w", err)
	}
	var token string
	if err := json.Unmarshal(raw, &token); err != nil {
		return fmt.Errorf("user.login unmarshal: %w", err)
	}
	if token == "" {
		return fmt.Errorf("user.login returned empty token")
	}
	c.apiToken = token
	return nil
}

// Host é a forma normalizada que o agent passa ao backend. Mais campos podem
// entrar com o tempo (templates, groups, severity) — mantidos compactos para
// o V1 do sync ser objetivo.
type Host struct {
	HostID     string `json:"hostid"`
	Host       string `json:"host"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	PrimaryIP  string `json:"primary_ip,omitempty"`
	PrimaryDNS string `json:"primary_dns,omitempty"`
}

type rawHost struct {
	HostID     string         `json:"hostid"`
	Host       string         `json:"host"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Interfaces []rawInterface `json:"interfaces"`
}

type rawInterface struct {
	IP   string `json:"ip"`
	DNS  string `json:"dns"`
	Main string `json:"main"`
	Type string `json:"type"`
}

// GetHosts puxa todos os hosts (sem paginação por enquanto — Zabbix devolve
// até 100k sem reclamar pra host.get; quando virar gargalo, paginar via
// `offset` + `limit`). Inclui interface primária (main=1).
//
// hostgroupIDs (opcional) filtra por grupo. nil = todos.
func (c *Client) GetHosts(ctx context.Context, hostgroupIDs []int) ([]Host, error) {
	params := map[string]any{
		"output":           []string{"hostid", "host", "name", "status"},
		"selectInterfaces": []string{"interfaceid", "ip", "dns", "main", "type"},
	}
	if len(hostgroupIDs) > 0 {
		params["groupids"] = hostgroupIDs
	}

	raw, err := c.call(ctx, "host.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("host.get: %w", err)
	}

	var rawHosts []rawHost
	if err := json.Unmarshal(raw, &rawHosts); err != nil {
		return nil, fmt.Errorf("host.get unmarshal: %w", err)
	}

	out := make([]Host, 0, len(rawHosts))
	for _, rh := range rawHosts {
		h := Host{
			HostID: rh.HostID,
			Host:   rh.Host,
			Name:   rh.Name,
			Status: rh.Status,
		}
		// Escolhe interface main=1; cai pra primeira disponível se não houver.
		for _, ifc := range rh.Interfaces {
			if ifc.Main == "1" {
				h.PrimaryIP = ifc.IP
				h.PrimaryDNS = ifc.DNS
				break
			}
		}
		if h.PrimaryIP == "" && len(rh.Interfaces) > 0 {
			h.PrimaryIP = rh.Interfaces[0].IP
			h.PrimaryDNS = rh.Interfaces[0].DNS
		}
		out = append(out, h)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Item é a definição de um item Zabbix (template/host item). value_type:
//   0=float, 1=character/string, 2=log, 3=unsigned int, 4=text.
// Bridge só usa value_type 0 e 3 (numéricos) — strings/logs não viram
// série temporal no VM.
type Item struct {
	ItemID    string `json:"itemid"`
	HostID    string `json:"hostid"`
	Key       string `json:"key_"`
	Name      string `json:"name"`
	ValueType string `json:"value_type"`
	Units     string `json:"units"`
}

// GetItems puxa items de uma lista de hostIDs. searchKeys aplica filtro por
// substring nas keys (Zabbix `search.key_` + searchByAny=true) — útil pra
// limitar pra system.cpu.*, vm.memory.*, vfs.fs.*, etc. searchKeys vazio =
// pega tudo (cuidado: pode ser grande).
//
// Só retorna items habilitados (status=0) e numéricos (value_type 0 ou 3).
func (c *Client) GetItems(ctx context.Context, hostIDs, searchKeys []string) ([]Item, error) {
	params := map[string]any{
		"output":  []string{"itemid", "hostid", "key_", "name", "value_type", "units"},
		"hostids": hostIDs,
		"filter": map[string]any{
			"status":     0,                // 0 = enabled
			"value_type": []int{0, 3},      // float, unsigned int
		},
	}
	if len(searchKeys) > 0 {
		searchMap := map[string]any{"key_": searchKeys}
		params["search"] = searchMap
		params["searchByAny"] = true
		params["startSearch"] = true
	}

	raw, err := c.call(ctx, "item.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("item.get: %w", err)
	}
	var items []Item
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("item.get unmarshal: %w", err)
	}
	return items, nil
}

// HistoryPoint é um datapoint numérico retornado pelo history.get.
type HistoryPoint struct {
	ItemID    string
	Timestamp time.Time
	Value     float64
}

type rawHistoryPoint struct {
	ItemID string `json:"itemid"`
	Clock  string `json:"clock"`
	Value  string `json:"value"`
	Ns     string `json:"ns"`
}

// GetHistory busca pontos de history pros items entre `since` e agora.
// O Zabbix exige `history` (tipo) por value_type — então a função separa
// items por tipo e faz uma chamada por tipo. Retorna tudo merged.
//
// `limit` por chamada protege contra series barulhentas; pra uma janela
// de 60s isso raramente é hit.
func (c *Client) GetHistory(ctx context.Context, items []Item, since time.Time, limit int) ([]HistoryPoint, error) {
	if len(items) == 0 {
		return nil, nil
	}
	// Agrupa item IDs por value_type. history.get só aceita 1 tipo por call.
	byType := map[string][]string{}
	for _, it := range items {
		byType[it.ValueType] = append(byType[it.ValueType], it.ItemID)
	}

	out := make([]HistoryPoint, 0, len(items)*2)
	for valueType, ids := range byType {
		if len(ids) == 0 {
			continue
		}
		params := map[string]any{
			"output":    "extend",
			"history":   valueType,
			"itemids":   ids,
			"time_from": since.Unix(),
			"sortfield": "clock",
			"sortorder": "ASC",
		}
		if limit > 0 {
			params["limit"] = limit
		}
		raw, err := c.call(ctx, "history.get", params, true)
		if err != nil {
			return nil, fmt.Errorf("history.get vt=%s: %w", valueType, err)
		}
		var pts []rawHistoryPoint
		if err := json.Unmarshal(raw, &pts); err != nil {
			return nil, fmt.Errorf("history.get unmarshal vt=%s: %w", valueType, err)
		}
		for _, p := range pts {
			clock := parseInt64(p.Clock)
			val := parseFloat64(p.Value)
			out = append(out, HistoryPoint{
				ItemID:    p.ItemID,
				Timestamp: time.Unix(clock, 0),
				Value:     val,
			})
		}
	}
	return out, nil
}

func parseInt64(s string) int64 {
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n
}

func parseFloat64(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// ---- Inventory (read-only) — Fase 1 da feature de gestão de items/triggers ----
//
// As funções abaixo são *somente leitura*. As escritas correspondentes
// (item.create, trigger.delete, etc) virão na Fase 2 e seguirão a mesma
// arquitetura de migration steps: agent recebe comando via mTLS step queue
// e executa contra o Zabbix. NUNCA o backend chama o Zabbix diretamente —
// o agent é a única ponte autorizada.

// ItemFull é a versão completa de Item usada pelo cache de inventário,
// incluindo campos de status (state, error, last_value, etc) que GetItems
// (usado pelo bridge de métricas) não traz.
type ItemFull struct {
	ItemID     string `json:"itemid"`
	HostID     string `json:"hostid"`
	Key        string `json:"key_"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	ValueType  string `json:"value_type"`
	Status     string `json:"status"`
	State      string `json:"state"`
	Delay      string `json:"delay"`
	Units      string `json:"units"`
	Error      string `json:"error"`
	LastValue  string `json:"lastvalue"`
	LastClock  string `json:"lastclock"`
	TemplateID string `json:"templateid"`
}

// GetItemsFull busca todos os items dos hostIDs informados, com campos de
// status. Sem filtro por value_type — queremos tudo (incluindo texto/log)
// pra a UI de inventário.
func (c *Client) GetItemsFull(ctx context.Context, hostIDs []string) ([]ItemFull, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	params := map[string]any{
		"output": []string{
			"itemid", "hostid", "key_", "name", "type", "value_type",
			"status", "state", "delay", "units", "error",
			"lastvalue", "lastclock", "templateid",
		},
		"hostids": hostIDs,
	}
	raw, err := c.call(ctx, "item.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("item.get (full): %w", err)
	}
	var items []ItemFull
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("item.get full unmarshal: %w", err)
	}
	return items, nil
}

// Trigger é a forma normalizada de trigger.get. Hosts é populado via
// selectHosts pra resolver multi-host triggers (expressões com items de
// múltiplos hosts).
type Trigger struct {
	TriggerID   string   `json:"triggerid"`
	Description string   `json:"description"`
	Expression  string   `json:"expression"`
	Priority    string   `json:"priority"`
	Status      string   `json:"status"`
	State       string   `json:"state"`
	Value       string   `json:"value"`
	Error       string   `json:"error"`
	LastChange  string   `json:"lastchange"`
	TemplateID  string   `json:"templateid"`
	HostIDs     []string `json:"-"` // populado via selectHosts
}

type rawTrigger struct {
	TriggerID   string `json:"triggerid"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
	Priority    string `json:"priority"`
	Status      string `json:"status"`
	State       string `json:"state"`
	Value       string `json:"value"`
	Error       string `json:"error"`
	LastChange  string `json:"lastchange"`
	TemplateID  string `json:"templateid"`
	Hosts       []struct {
		HostID string `json:"hostid"`
	} `json:"hosts"`
}

// GetTriggers busca todos os triggers dos hostIDs informados, com hosts
// envolvidos (pra suportar triggers cross-host).
func (c *Client) GetTriggers(ctx context.Context, hostIDs []string) ([]Trigger, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	params := map[string]any{
		"output": []string{
			"triggerid", "description", "expression", "priority",
			"status", "state", "value", "error", "lastchange", "templateid",
		},
		"hostids":         hostIDs,
		"selectHosts":     []string{"hostid"},
		"expandDescription": true,
	}
	raw, err := c.call(ctx, "trigger.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("trigger.get: %w", err)
	}
	var rts []rawTrigger
	if err := json.Unmarshal(raw, &rts); err != nil {
		return nil, fmt.Errorf("trigger.get unmarshal: %w", err)
	}
	out := make([]Trigger, 0, len(rts))
	for _, rt := range rts {
		t := Trigger{
			TriggerID: rt.TriggerID, Description: rt.Description,
			Expression: rt.Expression, Priority: rt.Priority,
			Status: rt.Status, State: rt.State, Value: rt.Value,
			Error: rt.Error, LastChange: rt.LastChange, TemplateID: rt.TemplateID,
		}
		for _, h := range rt.Hosts {
			t.HostIDs = append(t.HostIDs, h.HostID)
		}
		out = append(out, t)
	}
	return out, nil
}

// Problem é um evento ativo (PROBLEM state) retornado por problem.get.
// Hosts é resolvido via selectHosts; trigger via objectid (eventos de
// problema têm source=0/object=0 = trigger event).
type Problem struct {
	EventID      string   `json:"eventid"`
	TriggerID    string   `json:"objectid"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Clock        string   `json:"clock"`
	Acknowledged string   `json:"acknowledged"`
	HostIDs      []string `json:"-"`
}

type rawProblem struct {
	EventID      string `json:"eventid"`
	TriggerID    string `json:"objectid"`
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Clock        string `json:"clock"`
	Acknowledged string `json:"acknowledged"`
	Hosts        []struct {
		HostID string `json:"hostid"`
	} `json:"hosts"`
}

// ---- Inventory writes (Fase 2) ----
//
// Funções abaixo são *escrita* contra Zabbix JSON-RPC. Só são chamadas pelo
// agent (worker zabbix_ops.go) processando ops da fila zabbix_inventory_op.
// O backend Quarkus nunca chama estas funções — ele só enfileira ops via mTLS.

// HostDetail é a forma rica de host.get que vai pro cache (zabbix_host_detail).
// Reúne tudo que o form de edição precisa em uma chamada só.
type HostDetail struct {
	HostID       string                 `json:"hostid"`
	VisibleName  string                 `json:"name"`
	Hostname     string                 `json:"host"`
	Description  string                 `json:"description"`
	Status       string                 `json:"status"`
	Interfaces   []map[string]any       `json:"interfaces"`
	Groups       []map[string]any       `json:"groups"`
	ParentTpls   []map[string]any       `json:"parentTemplates"`
	Tags         []map[string]any       `json:"tags"`
	Macros       []map[string]any       `json:"macros"`
}

// GetHostsDetails faz um host.get rico — interfaces + grupos + templates +
// tags + macros — pros hostIDs informados. Usado pelo ciclo de inventory
// pra cachear o detalhe que o form de edição mostra.
func (c *Client) GetHostsDetails(ctx context.Context, hostIDs []string) ([]HostDetail, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	params := map[string]any{
		"output": []string{"hostid", "host", "name", "description", "status"},
		"hostids": hostIDs,
		"selectInterfaces":      []string{"interfaceid", "type", "ip", "dns", "port",
			"useip", "main", "details"},
		"selectGroups":          []string{"groupid", "name"},
		"selectParentTemplates": []string{"templateid", "name"},
		"selectTags":            "extend",
		"selectMacros":          "extend",
	}
	raw, err := c.call(ctx, "host.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("host.get (details): %w", err)
	}
	var out []HostDetail
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("host.get details unmarshal: %w", err)
	}
	return out, nil
}

// UpdateHost atualiza um host. fields deve conter hostid + qualquer combinação
// de name, host, description, status, interfaces, groups, templates, macros, tags.
//
// Importante: groups/templates/macros/tags em host.update SUBSTITUEM o set
// completo (mass replace). Pra preservar o que não foi mexido, o caller
// envia o set final desejado (não delta).
func (c *Client) UpdateHost(ctx context.Context, fields map[string]any) (string, error) {
	if _, ok := fields["hostid"]; !ok {
		return "", fmt.Errorf("host.update: missing hostid")
	}
	raw, err := c.call(ctx, "host.update", fields, true)
	if err != nil {
		return "", fmt.Errorf("host.update: %w", err)
	}
	return extractFirstID(raw, "hostids")
}

// CreateItem cria um item Zabbix. fields deve conter no mínimo
// hostid + name + key_ + type + value_type + delay (e mais conforme o type).
// Retorna o novo itemid.
func (c *Client) CreateItem(ctx context.Context, fields map[string]any) (string, error) {
	raw, err := c.call(ctx, "item.create", fields, true)
	if err != nil {
		return "", fmt.Errorf("item.create: %w", err)
	}
	return extractFirstID(raw, "itemids")
}

// UpdateItem atualiza um item existente. fields deve conter itemid e
// pelo menos um campo a alterar.
func (c *Client) UpdateItem(ctx context.Context, fields map[string]any) (string, error) {
	if _, ok := fields["itemid"]; !ok {
		return "", fmt.Errorf("item.update: missing itemid")
	}
	raw, err := c.call(ctx, "item.update", fields, true)
	if err != nil {
		return "", fmt.Errorf("item.update: %w", err)
	}
	return extractFirstID(raw, "itemids")
}

// DeleteItem deleta um ou mais items por itemid. Retorna a lista de
// itemids efetivamente removidos pelo Zabbix.
func (c *Client) DeleteItem(ctx context.Context, itemIDs []string) ([]string, error) {
	if len(itemIDs) == 0 {
		return nil, fmt.Errorf("item.delete: empty list")
	}
	raw, err := c.call(ctx, "item.delete", itemIDs, true)
	if err != nil {
		return nil, fmt.Errorf("item.delete: %w", err)
	}
	return extractIDs(raw, "itemids")
}

// GetItemForClone busca os campos cloneáveis de um item pelo itemid.
// Retorna o map cru pra que o caller possa filtrar + sobrescrever.
func (c *Client) GetItemForClone(ctx context.Context, itemID string) (map[string]any, error) {
	params := map[string]any{
		"output":  "extend",
		"itemids": []string{itemID},
	}
	raw, err := c.call(ctx, "item.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("item.get for clone: %w", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("item.get clone unmarshal: %w", err)
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("item.get for clone: itemid %s not found", itemID)
	}
	return arr[0], nil
}

// CreateTrigger cria um trigger. fields deve conter pelo menos description
// + expression (o Zabbix resolve hosts pela expression).
func (c *Client) CreateTrigger(ctx context.Context, fields map[string]any) (string, error) {
	raw, err := c.call(ctx, "trigger.create", fields, true)
	if err != nil {
		return "", fmt.Errorf("trigger.create: %w", err)
	}
	return extractFirstID(raw, "triggerids")
}

// UpdateTrigger atualiza um trigger. fields deve conter triggerid + algo.
func (c *Client) UpdateTrigger(ctx context.Context, fields map[string]any) (string, error) {
	if _, ok := fields["triggerid"]; !ok {
		return "", fmt.Errorf("trigger.update: missing triggerid")
	}
	raw, err := c.call(ctx, "trigger.update", fields, true)
	if err != nil {
		return "", fmt.Errorf("trigger.update: %w", err)
	}
	return extractFirstID(raw, "triggerids")
}

// DeleteTrigger deleta um ou mais triggers.
func (c *Client) DeleteTrigger(ctx context.Context, triggerIDs []string) ([]string, error) {
	if len(triggerIDs) == 0 {
		return nil, fmt.Errorf("trigger.delete: empty list")
	}
	raw, err := c.call(ctx, "trigger.delete", triggerIDs, true)
	if err != nil {
		return nil, fmt.Errorf("trigger.delete: %w", err)
	}
	return extractIDs(raw, "triggerids")
}

// GetTriggerForClone busca campos cloneáveis pelo triggerid.
func (c *Client) GetTriggerForClone(ctx context.Context, triggerID string) (map[string]any, error) {
	params := map[string]any{
		"output":     "extend",
		"triggerids": []string{triggerID},
	}
	raw, err := c.call(ctx, "trigger.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("trigger.get for clone: %w", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("trigger.get clone unmarshal: %w", err)
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("trigger.get for clone: triggerid %s not found", triggerID)
	}
	return arr[0], nil
}

// extractFirstID lê o primeiro elemento de result.<arrayKey>. Zabbix
// devolve `{"itemids": ["123"]}` em item.create — vamos pegar "123".
func extractFirstID(raw json.RawMessage, arrayKey string) (string, error) {
	ids, err := extractIDs(raw, arrayKey)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no %s in response", arrayKey)
	}
	return ids[0], nil
}

// extractIDs aceita os dois formatos comuns de retorno do Zabbix:
//
//	{"itemids": ["1","2"]}  (números viraram strings; comum em 5.0+)
//	{"itemids": [1, 2]}     (legacy 4.x)
func extractIDs(raw json.RawMessage, arrayKey string) ([]string, error) {
	var asStr map[string][]string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		if v, ok := asStr[arrayKey]; ok {
			return v, nil
		}
	}
	var asAny map[string][]any
	if err := json.Unmarshal(raw, &asAny); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", arrayKey, err)
	}
	arr, ok := asAny[arrayKey]
	if !ok {
		return nil, fmt.Errorf("key %s missing in response", arrayKey)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		out = append(out, fmt.Sprintf("%v", v))
	}
	return out, nil
}

// GetProblems busca problemas ativos (recent=true; resolved são excluídos
// por default no problem.get). hostIDs filtra; vazio = todos.
//
// Importante: Zabbix 7.0+ removeu `selectHosts` de problem.get. Em vez disso,
// buscamos hosts via trigger.get usando objectid (triggerid) dos problemas.
// Pra 5.x/6.x ainda funcionaria com selectHosts, mas a versão sem o param
// é compatível com ambos.
func (c *Client) GetProblems(ctx context.Context, hostIDs []string) ([]Problem, error) {
	params := map[string]any{
		"output":      []string{"eventid", "objectid", "name", "severity", "clock", "acknowledged"},
		"recent":      true,                 // só problemas atuais (não resolvidos)
		"source":      0,                    // trigger event
		"object":      0,                    // trigger
		"sortfield":   []string{"eventid"},
		"sortorder":   "DESC",
		"limit":       5000,
	}
	if len(hostIDs) > 0 {
		params["hostids"] = hostIDs
	}
	raw, err := c.call(ctx, "problem.get", params, true)
	if err != nil {
		return nil, fmt.Errorf("problem.get: %w", err)
	}
	var rps []rawProblem
	if err := json.Unmarshal(raw, &rps); err != nil {
		return nil, fmt.Errorf("problem.get unmarshal: %w", err)
	}
	out := make([]Problem, 0, len(rps))
	triggerIDs := make([]string, 0, len(rps))
	for _, rp := range rps {
		out = append(out, Problem{
			EventID: rp.EventID, TriggerID: rp.TriggerID,
			Name: rp.Name, Severity: rp.Severity, Clock: rp.Clock,
			Acknowledged: rp.Acknowledged,
		})
		triggerIDs = append(triggerIDs, rp.TriggerID)
	}
	// Resolve hostids dos triggers num único trigger.get — barato (uma chamada
	// adicional vs N chamadas). Mantém compat com Zabbix 5/6/7.
	if len(triggerIDs) > 0 {
		trigHosts, err := c.triggerHostsByID(ctx, triggerIDs)
		if err == nil {
			for i := range out {
				if hs, ok := trigHosts[out[i].TriggerID]; ok {
					out[i].HostIDs = hs
				}
			}
		}
	}
	return out, nil
}

// triggerHostsByID retorna mapa triggerid → [hostids] via trigger.get com
// selectHosts (suportado em todas versões). Usado pra recuperar a info que
// problem.get não dá mais em Zabbix 7.
func (c *Client) triggerHostsByID(ctx context.Context, triggerIDs []string) (map[string][]string, error) {
	raw, err := c.call(ctx, "trigger.get", map[string]any{
		"output":      []string{"triggerid"},
		"triggerids":  triggerIDs,
		"selectHosts": []string{"hostid"},
	}, true)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		TriggerID string `json:"triggerid"`
		Hosts     []struct {
			HostID string `json:"hostid"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(rows))
	for _, r := range rows {
		hs := make([]string, 0, len(r.Hosts))
		for _, h := range r.Hosts {
			hs = append(hs, h.HostID)
		}
		out[r.TriggerID] = hs
	}
	return out, nil
}
