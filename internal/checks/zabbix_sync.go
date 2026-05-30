// zabbix_sync.go — Check "zabbix.sync" — sincroniza hosts/eventos do Zabbix
// do cliente com o ispwatch.
//
// Status atual (Plan 04 do Phase 6, "zabbix-on-prem"):
//   - V0 (este arquivo) — STUB. Valida params recebidos via config-pull,
//     loga ack + um summary do que vai monitorar. Emite uma métrica
//     `zabbix.sync.tick = 1` por ciclo pra confirmar visibilidade no NOC.
//   - V1 (próxima) — cliente JSON-RPC real: user.login (USERNAME_PASSWORD)
//     ou Authorization: Bearer (API_TOKEN), host.get, problem.get,
//     mediatype.create. Emite host upserts via gRPC ReportTopology +
//     alerts via gRPC StreamAlerts (proto novo).
//   - V2 — servidor HTTP local em webhook_port que recebe payload da
//     media-type provisionada no Zabbix, valida webhook_token, normaliza
//     evento e enfileira no WAL pra entrega ao backend.
//
// Os params chegam decifrados — backend faz tinkAead.decrypt() antes de
// enviar via config-pull. O canal é mTLS (HTTPS+cert). Não logamos segredo
// em log (só preview ••••XXXX).
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/agentstate"
	"github.com/ispwatch/collector/internal/zabbix"
)

// zabbixSyncCheck é a implementação concreta de Check pra "zabbix.sync".
type zabbixSyncCheck struct {
	id             string
	interval       time.Duration
	monitorID      string
	baseURL        string
	authType       string
	username       string
	password       string // em claro (decifrado pelo backend antes do config-pull)
	apiToken       string
	validateTLS    bool
	timeoutSeconds int
	webhookPort    int
	webhookToken   string
	filters        zabbixFilterSpec
	logFilePath    string // caminho customizado pro zabbix_server.log; "" = default
	staticTags     map[string]string
	log            *slog.Logger

	// lastBridge mantém o timestamp do último ponto sincronizado. No
	// próximo tick, history.get usa esse valor como time_from pra evitar
	// duplicação. Inicia em zero — primeiro tick puxa últimos `interval`.
	lastBridge time.Time

	// lastConfigShip é a hora do último envio de zabbix_*.conf pro backend.
	// Cadência baixa (a cada ~5min) — mudanças no conf são raras.
	lastConfigShip time.Time

	// lastInventoryShip controla a cadência do item.get + trigger.get (5min);
	// problem.get tem cadência própria (1min) — sempre que (now - lastProblemsShip)
	// >= 1min.
	lastInventoryShip time.Time
	lastProblemsShip  time.Time
}

// zabbixFilterSpec espelha o JSON salvo em zabbix_monitor.filters.
type zabbixFilterSpec struct {
	SeverityMin      string   `json:"severity_min"`
	TriggerNameAllow string   `json:"trigger_name_allow"`
	TriggerNameDeny  string   `json:"trigger_name_deny"`
	HostgroupIDs     []int    `json:"hostgroup_ids"`
	TagFilters       []map[string]string `json:"tag_filters"`
}

func newZabbixSyncCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()

	monitorID := params["monitor_id"]
	baseURL := params["base_url"]
	if baseURL == "" {
		return nil, fmt.Errorf("zabbix.sync: missing param 'base_url'")
	}
	authType := params["auth_type"]
	if authType == "" {
		authType = "API_TOKEN"
	}
	if authType != "API_TOKEN" && authType != "USERNAME_PASSWORD" {
		return nil, fmt.Errorf("zabbix.sync: invalid auth_type %q", authType)
	}

	timeoutSec := parseIntParam(params, "timeout_seconds", 10)
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	webhookPort := parseIntParam(params, "webhook_port", 9876)
	if webhookPort <= 0 || webhookPort > 65535 {
		webhookPort = 9876
	}

	validateTLS := params["validate_tls"] != "false"

	// local_host_id (opcional): noc_host que representa o servidor físico
	// onde este agent roda. Aplica via agentstate pra selfmetrics duplicar
	// suas métricas com host_id=<localHostID>, fazendo CPU/mem/disk do
	// host real aparecer nos gráficos do noc_host correspondente. 0 = não
	// amarrar (default).
	localHostID := int64(parseIntParam(params, "local_host_id", 0))
	agentstate.SetLocalHostID(localHostID)

	var filters zabbixFilterSpec
	if raw := params["filters"]; raw != "" {
		// O backend serializa o jsonb como string e injeta no param. Se
		// vier malformado, seguimos com defaults — log warn no Run().
		_ = json.Unmarshal([]byte(raw), &filters)
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "zabbix.sync-" + monitorID
	}

	tags := make(map[string]string, len(cfg.GetStaticTags())+2)
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	tags["monitor_id"] = monitorID
	tags["source"] = "zabbix"

	return &zabbixSyncCheck{
		id:             id,
		interval:       interval,
		monitorID:      monitorID,
		baseURL:        baseURL,
		authType:       authType,
		username:       params["username"],
		password:       params["password"],
		apiToken:       params["api_token"],
		validateTLS:    validateTLS,
		timeoutSeconds: timeoutSec,
		webhookPort:    webhookPort,
		webhookToken:   params["webhook_token"],
		filters:        filters,
		logFilePath:    params["log_file_path"],
		staticTags:     tags,
		log:            slog.Default().With("check", "zabbix.sync", "monitor_id", monitorID),
	}, nil
}

func (c *zabbixSyncCheck) ID() string                  { return c.id }
func (c *zabbixSyncCheck) Interval() time.Duration     { return c.interval }
func (c *zabbixSyncCheck) Tags() map[string]string     { return c.staticTags }

// Run V1: chama Zabbix JSON-RPC (apiinfo.version + host.get) e posta o
// resultado normalizado no endpoint mTLS do backend (/api/collector/v1/zabbix/hosts).
// V2 adiciona problem.get + media-type provisioning + webhook listener — ainda TODO.
//
// Métricas emitidas por ciclo:
//   - zabbix.sync.tick = 1 (sempre, mesmo em erro — pro NOC ver "sync vivo")
//   - zabbix.sync.hosts_imported = <count> (só em caminho feliz)
//   - zabbix.sync.errors = 1 (qualquer falha de auth/RPC/ingest)
//
// Erros não derrubam o ciclo seguinte: scheduler ignora retorno != nil e reagenda.
func (c *zabbixSyncCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	timeout := time.Duration(c.timeoutSeconds) * time.Second
	// Janela ampla cobre host.get + POST backend; cada call interna tem
	// seu próprio timeout do client http (= c.timeoutSeconds).
	rctx, cancel := context.WithTimeout(ctx, timeout*3+10*time.Second)
	defer cancel()

	authType := zabbix.AuthAPIToken
	if c.authType == "USERNAME_PASSWORD" {
		authType = zabbix.AuthUsernamePassword
	}
	cli := zabbix.New(c.baseURL, authType, c.username, c.password, c.apiToken,
		c.validateTLS, timeout)

	if err := cli.Login(rctx); err != nil {
		c.log.Warn("zabbix.sync login failed", "err", err)
		return c.errorMetrics("login_failed"), nil
	}
	version, err := cli.Version(rctx)
	if err != nil {
		// apiinfo.version é só sanity — não falha o ciclo se errar (proxy
		// reverso pode estar tratando rotas diferente). Loga e segue.
		c.log.Warn("zabbix.sync apiinfo.version failed (continuing)", "err", err)
	}

	hosts, err := cli.GetHosts(rctx, c.filters.HostgroupIDs)
	if err != nil {
		c.log.Warn("zabbix.sync host.get failed", "err", err)
		return c.errorMetrics("host_get_failed"), nil
	}

	type ingestPayload struct {
		MonitorID     string        `json:"monitor_id"`
		ZabbixVersion string        `json:"zabbix_version,omitempty"`
		Hosts         []zabbix.Host `json:"hosts"`
	}
	body, err := PostJSON(rctx, "/api/collector/v1/zabbix/hosts", ingestPayload{
		MonitorID:     c.monitorID,
		ZabbixVersion: version,
		Hosts:         hosts,
	})
	if err != nil {
		c.log.Warn("zabbix.sync ingest failed", "err", err, "body", truncateString(string(body), 200))
		return c.errorMetrics("ingest_failed"), nil
	}

	// Mapping zabbix_hostid → noc_host_uuid (retornado pelo backend). Usado
	// pra taggear métricas vindas via item.get/history.get com o host_id
	// ISPWatch.
	hostMap := parseHostMap(body)

	// Bridge de métricas: item.get + history.get para os hostids importados.
	// Sem filtro de keys por enquanto (universo já é pequeno). since = última
	// sync ou (now - interval) no primeiro tick.
	hostIDs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		hostIDs = append(hostIDs, h.HostID)
	}
	since := c.lastBridge
	if since.IsZero() {
		since = time.Now().Add(-c.interval)
	}

	bridgedMetrics, bridgeErr := c.bridgeMetrics(rctx, cli, hostIDs, hostMap, since)
	if bridgeErr != nil {
		c.log.Warn("zabbix.sync bridge failed (hosts ok)", "err", bridgeErr)
		// Não fail o ciclo — sync de hosts já passou, métricas de items são
		// secundárias. Próximo tick tenta de novo.
	} else {
		c.lastBridge = time.Now()
	}

	// Ship dos arquivos de configuração — a cada 5min, ou no first tick.
	// Falhas (arquivo ausente, sem permissão, backend offline) não derrubam
	// o ciclo; só loga. O backend deduplica por sha256, então ship repetido
	// é barato.
	if c.lastConfigShip.IsZero() || time.Since(c.lastConfigShip) >= 5*time.Minute {
		c.shipConfigFiles(rctx)
		c.lastConfigShip = time.Now()
	}

	// Aplica changes pending do UI editor — sempre roda, pra que mudanças
	// de operator sejam aplicadas no próximo tick (~1 min de latência).
	c.applyPendingChanges(rctx)

	// Tail incremental do zabbix_server.log — roda a cada tick (60s default).
	// Sem arquivo / sem permissão → no-op silencioso. Erros de POST não
	// derrubam o ciclo; cursor local só avança após ack.
	if sent, err := c.shipLogTail(rctx); err != nil {
		c.log.Warn("zabbix.sync log tail failed", "err", err, "sent_so_far", sent)
	} else if sent > 0 {
		c.log.Info("zabbix.sync log tail shipped", "events", sent)
	}

	// Inventory: items + triggers a cada 5min (cardinalidade grande),
	// problems a cada 1min (cardinalidade pequena, freshness importa).
	// hostIDs já foi montado no bridge de métricas acima.
	if c.lastInventoryShip.IsZero() || time.Since(c.lastInventoryShip) >= 5*time.Minute {
		if err := c.shipInventory(rctx, cli, hostIDs); err != nil {
			c.log.Warn("zabbix.sync inventory ship failed", "err", err)
		} else {
			c.lastInventoryShip = time.Now()
		}
		// Junto: detalhes ricos por host (interfaces/groups/templates/tags/macros).
		// Mesma cadência — é uma chamada host.get extra com selects pesados,
		// mas paga só a cada 5min.
		if err := c.shipHostDetails(rctx, cli, hostIDs); err != nil {
			c.log.Warn("zabbix.sync host details ship failed", "err", err)
		}
	}
	if c.lastProblemsShip.IsZero() || time.Since(c.lastProblemsShip) >= 1*time.Minute {
		if err := c.shipProblems(rctx, cli, hostIDs); err != nil {
			c.log.Warn("zabbix.sync problems ship failed", "err", err)
		} else {
			c.lastProblemsShip = time.Now()
		}
	}

	// Migration steps — pega no máximo UM step por tick. Steps longos
	// (pg_dump de 50GB pode levar ~30min) usam um ctx com deadline maior
	// que o rctx normal pra não morrer no meio. O loop só avança quando
	// o backend marca succeeded; failed para tudo.
	migrationCtx, migrationCancel := context.WithTimeout(ctx, 2*time.Hour)
	if ran, err := c.fetchAndExecOneStep(migrationCtx); err != nil {
		c.log.Warn("migration step failed", "err", err, "ran", ran)
	}
	migrationCancel()

	// Inventory ops (CRUD em items/triggers do Zabbix via UI). Backend
	// enfileira; agent executa via JSON-RPC. Mesmo ciclo de uma op por
	// tick — operações são rápidas, mas preservar ordem do operador.
	if _, err := c.fetchAndExecOneOp(rctx, cli); err != nil {
		c.log.Warn("zabbix inventory op failed", "err", err)
	}

	c.log.Info("zabbix.sync ok",
		"version", version,
		"hosts_in_zabbix", len(hosts),
		"bridged_points", len(bridgedMetrics),
	)

	now := timestamppb.Now()
	out := make([]*collectorv1.Metric, 0, len(bridgedMetrics)+2)
	out = append(out,
		&collectorv1.Metric{Time: now, HostId: c.monitorID, MetricName: "zabbix.sync.tick", Value: 1, Tags: c.staticTags, Source: "zabbix"},
		&collectorv1.Metric{Time: now, HostId: c.monitorID, MetricName: "zabbix.sync.hosts_imported", Value: float64(len(hosts)), Tags: c.staticTags, Source: "zabbix"},
	)
	out = append(out, bridgedMetrics...)
	return out, nil
}

// bridgeMetrics busca items + history pros hosts e converte cada datapoint
// numa collectorv1.Metric ISPWatch. host_id é o noc_host_uuid (do mapping)
// porque é o que casa com noc_host no front e no alerting.
func (c *zabbixSyncCheck) bridgeMetrics(
	ctx context.Context,
	cli *zabbix.Client,
	hostIDs []string,
	hostMap map[string]hostMapping,
	since time.Time,
) ([]*collectorv1.Metric, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	items, err := cli.GetItems(ctx, hostIDs, nil)
	if err != nil {
		return nil, fmt.Errorf("item.get: %w", err)
	}
	if len(items) == 0 {
		return nil, nil
	}
	// Indexa items por ItemID pra resolver hostid/key/units no loop de pontos.
	idx := make(map[string]zabbix.Item, len(items))
	for _, it := range items {
		idx[it.ItemID] = it
	}

	// limit=500 protege contra séries muito densas. Em uma janela de 60s
	// é folgado pro caso real (item polled a cada 30-60s).
	pts, err := cli.GetHistory(ctx, items, since, 500)
	if err != nil {
		return nil, fmt.Errorf("history.get: %w", err)
	}
	if len(pts) == 0 {
		return nil, nil
	}

	out := make([]*collectorv1.Metric, 0, len(pts))
	for _, p := range pts {
		it, ok := idx[p.ItemID]
		if !ok {
			continue
		}
		mapping, hasHost := hostMap[it.HostID]
		// host_id no VM precisa ser o bigint noc_host.id (string), porque é
		// o que MetricsSeriesResource usa no match{} ao consultar VM. UUID
		// não é indexado lá. Fallback pro zabbix hostid se mapping ausente.
		hostID := it.HostID
		if hasHost {
			hostID = fmt.Sprintf("%d", mapping.NocHostID)
		}
		tags := map[string]string{
			"monitor_id":     c.monitorID,
			"source":         "zabbix",
			"zabbix_hostid":  it.HostID,
			"zabbix_key":     it.Key,
			"zabbix_name":    it.Name,
			"noc_host_uuid":  mapping.NocHostUUID,
		}
		if it.Units != "" {
			tags["units"] = it.Units
		}
		out = append(out, &collectorv1.Metric{
			Time:       timestamppb.New(p.Timestamp),
			HostId:     hostID,
			MetricName: "zabbix." + sanitizeMetricName(it.Key),
			Value:      p.Value,
			Tags:       tags,
			Source:     "zabbix",
		})
	}
	return out, nil
}

// hostMapping reflete um entry do host_map devolvido por /zabbix/hosts.
type hostMapping struct {
	NocHostID   int64
	NocHostUUID string
}

// parseHostMap extrai o map de zabbix_hostid → noc info do JSON response.
func parseHostMap(body []byte) map[string]hostMapping {
	var resp struct {
		HostMap map[string]struct {
			NocHostID   int64  `json:"noc_host_id"`
			NocHostUUID string `json:"noc_host_uuid"`
		} `json:"host_map"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	out := make(map[string]hostMapping, len(resp.HostMap))
	for k, v := range resp.HostMap {
		out[k] = hostMapping{NocHostID: v.NocHostID, NocHostUUID: v.NocHostUUID}
	}
	return out
}

// sanitizeMetricName troca caracteres não-aceitos em nomes de métricas
// (`[`, `]`, `,`, espaço) por `_`. dots ficam — convenção ISPWatch
// (VmRemoteWriter converte pra underscores no VM antes do storage).
func sanitizeMetricName(key string) string {
	var sb []byte
	prevUnderscore := false
	for i := 0; i < len(key); i++ {
		ch := key[i]
		switch ch {
		case '[', ']', ',', ' ', '"', '\'':
			if !prevUnderscore {
				sb = append(sb, '_')
				prevUnderscore = true
			}
		default:
			sb = append(sb, ch)
			prevUnderscore = false
		}
	}
	// trim trailing underscores
	for len(sb) > 0 && sb[len(sb)-1] == '_' {
		sb = sb[:len(sb)-1]
	}
	return string(sb)
}

// errorMetrics monta o par tick=1 + errors=1 com tag reason. Emitir o tick
// mesmo em falha mantém continuidade no painel (linha não some); errors é
// o sinal real de alarme.
func (c *zabbixSyncCheck) errorMetrics(reason string) []*collectorv1.Metric {
	now := timestamppb.Now()
	tags := make(map[string]string, len(c.staticTags)+1)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["reason"] = reason
	return []*collectorv1.Metric{
		{Time: now, HostId: c.monitorID, MetricName: "zabbix.sync.tick", Value: 1, Tags: c.staticTags, Source: "zabbix"},
		{Time: now, HostId: c.monitorID, MetricName: "zabbix.sync.errors", Value: 1, Tags: tags, Source: "zabbix"},
	}
}

func (c *zabbixSyncCheck) hasCreds() bool {
	if c.authType == "API_TOKEN" {
		return c.apiToken != ""
	}
	return c.username != "" && c.password != ""
}

func init() {
	Default.Register("zabbix.sync", newZabbixSyncCheck)
}
