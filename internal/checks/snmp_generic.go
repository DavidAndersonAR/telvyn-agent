// snmp_generic.go — Check "snmp.generic" implementacao continua (Phase 3 Plan 02).
//
// O snmp.generic coleta um device SNMP segundo um perfil YAML bundled
// (linux-net-snmp, cisco-ios, cisco-nx-os, juniper-junos, mikrotik-routeros,
// generic-snmpv2). O perfil pode vir explicito em CheckConfig.params["profile"]
// ou ser resolvido automaticamente via sysObjectID GET na primeira Run().
//
// CHECK-02 do REQUIREMENTS.md fechado por este check + os 6 perfis bundled.
// CHECK-05 fechado pelo perfil mikrotik-routeros (cobertura via SNMP,
// nao via API binaria RouterOS — vide CONTEXT.md Phase 3).
//
// Parametros aceitos em cfg.Params:
//   target           "host[:port]"  obrigatorio
//   profile          "auto" | "<nome>" — default "auto"
//   version          "v2c" | "v3"   — default "v2c"
//   community        v2c
//   v3_user, v3_auth_proto, v3_auth_pass, v3_priv_proto, v3_priv_pass, v3_context
//   timeout_seconds  inteiro (default 5)

package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/snmp"
)

// DeviceMetadataPusher emite a identidade do device (metadata.device) pro gateway.
// Implementado por *otlp.IngestExporter. Injetado uma vez pelo runtime de ingest.
type DeviceMetadataPusher interface {
	PostDeviceMetadata(ctx context.Context, hostID string, device map[string]string) error
}

var deviceMetaPusher DeviceMetadataPusher

// SetDeviceMetadataPusher liga o emit de metadata.device (chamado no startIngestChecks).
func SetDeviceMetadataPusher(p DeviceMetadataPusher) { deviceMetaPusher = p }

// snmpClientFactory cria um Client conectavel. Em prod aponta para
// snmp.NewClient; testes injetam fake que ignora UDP.
type snmpClientFactory func(p snmp.Params) (snmpGenericRunner, error)

// snmpGenericRunner abstrai as operacoes que snmp.generic faz:
//   1. Get(ctx, [sysObjectID])   — para auto-detect
//   2. snmp.Profile.Collect(...) — para emitir metricas
//
// Em prod e um *snmp.Client embrulhado. No test e um stub.
type snmpGenericRunner interface {
	GetSysObjectID(ctx context.Context) (string, error)
	Collect(ctx context.Context, profile *snmp.Profile, hostID string, staticTags map[string]string) ([]*collectorv1.Metric, error)
	CollectDeviceMetadata(ctx context.Context, profile *snmp.Profile) map[string]string
	Close() error
}

// realRunner conecta o snmp.Client real a snmpGenericRunner.
type realRunner struct{ c *snmp.Client }

func (r *realRunner) GetSysObjectID(ctx context.Context) (string, error) {
	pdus, err := r.c.Get(ctx, []string{"1.3.6.1.2.1.1.2.0"})
	if err != nil {
		return "", err
	}
	if len(pdus) == 0 {
		return "", fmt.Errorf("snmp: sysObjectID nao retornado")
	}
	// Value vem como string "1.3.6.1.4.1.X.Y" ou ".1.3.6.1.4.1.X.Y".
	return fmt.Sprintf("%v", pdus[0].Value), nil
}

func (r *realRunner) Collect(ctx context.Context, profile *snmp.Profile, hostID string, staticTags map[string]string) ([]*collectorv1.Metric, error) {
	return profile.Collect(ctx, r.c, hostID, staticTags)
}

func (r *realRunner) CollectDeviceMetadata(ctx context.Context, profile *snmp.Profile) map[string]string {
	return profile.CollectDeviceMetadata(ctx, r.c)
}

func (r *realRunner) Close() error {
	if r.c == nil {
		return nil
	}
	return r.c.Close()
}

// defaultClientFactory e a factory de prod — chama snmp.NewClient e envolve.
var defaultClientFactory snmpClientFactory = func(p snmp.Params) (snmpGenericRunner, error) {
	c, err := snmp.NewClient(p)
	if err != nil {
		return nil, err
	}
	return &realRunner{c: c}, nil
}

// snmpGenericCheck e a implementacao concreta do Check para "snmp.generic".
type snmpGenericCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string

	params          snmp.Params
	profileID       string // "auto" ou nome explicito
	clientFn        snmpClientFactory
	disabledMetrics map[string]bool // métricas desabilitadas pelo usuário (per-host)

	mu             sync.Mutex
	resolved       *snmp.Profile // populado lazy quando profileID="auto"
	resolveAttempt bool          // ja tentamos auto-detect (sucesso ou fallback)
	lastMetaEmit   time.Time     // throttle do emit de metadata.device (15min)
}

// newSnmpGenericCheck e a Factory registrada em init() para "snmp.generic".
// Valida params (target obrigatorio, profile valido se nao "auto") e monta
// snmp.Params via helper ParamsFromMap.
func newSnmpGenericCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newSnmpGenericCheckWithFactory(cfg, defaultClientFactory)
}

func newSnmpGenericCheckWithFactory(cfg *collectorv1.CheckConfig, factory snmpClientFactory) (Check, error) {
	params := cfg.GetParams()

	snmpParams, err := snmp.ParamsFromMap(params)
	if err != nil {
		return nil, err
	}

	profileID := strings.TrimSpace(params["profile"])
	if profileID == "" {
		profileID = "auto"
	}

	// Se nao for "auto", o nome deve resolver agora (falhar early evita
	// surpresa na primeira Run).
	if profileID != "auto" {
		if _, err := snmp.LoadProfile(profileID); err != nil {
			return nil, err
		}
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "snmp.generic-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	// Parse disabled_metrics from params (JSON array string injected by configpull).
	disabled := make(map[string]bool)
	if dm := params["disabled_metrics"]; dm != "" {
		var names []string
		if err := json.Unmarshal([]byte(dm), &names); err == nil {
			for _, n := range names {
				disabled[n] = true
			}
		}
	}

	return &snmpGenericCheck{
		id:              id,
		interval:        interval,
		hostID:          cfg.GetHostId(),
		staticTags:      tags,
		params:          snmpParams,
		profileID:       profileID,
		clientFn:        factory,
		disabledMetrics: disabled,
	}, nil
}

func (c *snmpGenericCheck) ID() string              { return c.id }
func (c *snmpGenericCheck) Interval() time.Duration { return c.interval }
func (c *snmpGenericCheck) Tags() map[string]string { return c.staticTags }

// Run executa um ciclo de coleta. Em profile=auto, na primeira execucao
// faz um GET de sysObjectID, resolve via MatchSysObjectID, e cacheia.
// Fallback para "generic-snmpv2" se o sysObjectID nao casa nenhum.
//
// Cliente UDP e construido (e fechado) por execucao — mantemos o Client
// curto no escopo para nao reter socket entre intervals (intervals de
// 30s+ sao longos comparados ao custo de open/close UDP).
func (c *snmpGenericCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	runner, err := c.clientFn(c.params)
	if err != nil {
		return nil, err
	}
	defer runner.Close()

	profile, err := c.resolveProfile(ctx, runner)
	if err != nil {
		return nil, err
	}

	metrics, err := runner.Collect(ctx, profile, c.hostID, c.staticTags)
	// Identidade é independente da coleta de métricas: um profile pode falhar
	// em uma métrica específica enquanto os OIDs padrão de inventário respondem.
	// O erro da coleta continua sendo propagado abaixo.
	c.maybeEmitDeviceMetadata(ctx, runner, profile)
	if err != nil {
		return nil, err
	}

	// Filter out disabled metrics (per-host toggle from noc_host_disabled_metrics).
	if len(c.disabledMetrics) > 0 && len(metrics) > 0 {
		filtered := make([]*collectorv1.Metric, 0, len(metrics))
		for _, m := range metrics {
			if !c.disabledMetrics[m.MetricName] {
				filtered = append(filtered, m)
			}
		}
		metrics = filtered
	}

	return metrics, nil
}

// maybeEmitDeviceMetadata coleta e emite metadata.device no máximo a cada 15min
// (e na primeira execução). Fail-soft: nunca afeta a coleta de métricas.
func (c *snmpGenericCheck) maybeEmitDeviceMetadata(ctx context.Context, runner snmpGenericRunner, profile *snmp.Profile) {
	if deviceMetaPusher == nil || profile == nil {
		return
	}
	c.mu.Lock()
	due := c.lastMetaEmit.IsZero() || time.Since(c.lastMetaEmit) >= 15*time.Minute
	if due {
		c.lastMetaEmit = time.Now()
	}
	c.mu.Unlock()
	if !due {
		return
	}
	dev := runner.CollectDeviceMetadata(ctx, profile)
	if len(dev) == 0 {
		return
	}
	if err := deviceMetaPusher.PostDeviceMetadata(ctx, c.hostID, dev); err != nil {
		// fail-soft: só loga em nível baixo se houver logger; senão ignora.
		_ = err
	}
}

// resolveProfile retorna o perfil ativo. Caso profile=auto, faz GET
// sysObjectID na primeira chamada e cacheia o resultado (incluindo
// fallback para generic-snmpv2).
func (c *snmpGenericCheck) resolveProfile(ctx context.Context, runner snmpGenericRunner) (*snmp.Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.resolved != nil {
		return c.resolved, nil
	}

	if c.profileID != "auto" {
		p, err := snmp.LoadProfile(c.profileID)
		if err != nil {
			return nil, err
		}
		c.resolved = p
		return p, nil
	}

	// profile=auto
	sysOid, err := runner.GetSysObjectID(ctx)
	if err != nil {
		return nil, fmt.Errorf("snmp.generic auto-detect: %w", err)
	}
	all, err := snmp.AllProfiles()
	if err != nil {
		return nil, err
	}
	match, ok := snmp.MatchSysObjectID(all, sysOid)
	if !ok {
		// Fallback explicito — generic-snmpv2 e o catch-all bundled.
		match, err = snmp.LoadProfile("generic-snmpv2")
		if err != nil {
			return nil, fmt.Errorf("snmp.generic fallback generic-snmpv2: %w", err)
		}
	}
	c.resolved = match
	c.resolveAttempt = true
	return match, nil
}

// init auto-registra a factory no Registry Default. Plan 03-02 fecha
// CHECK-02 + CHECK-05 (reinterpretado) com este registro.
func init() {
	Default.Register("snmp.generic", newSnmpGenericCheck)
}
