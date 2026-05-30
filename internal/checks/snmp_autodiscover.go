// snmp_autodiscover.go — Check "snmp.autodiscover" (Phase 3 Plan 05).
//
// Escaneia CIDRs configurados via CheckConfig.params["cidrs"] usando
// discovery.ScanSNMP. Para cada Candidate, emite um Event com
// event_type="host.discovered" no canal global (events.go). Nao emite
// Metrics — autodiscovery e semantica de "estado descoberto", nao
// telemetria contínua.
//
// CHECK-07 fechado por este check + handler Quarkus AutodiscoveryHandler.
//
// Parametros aceitos em cfg.Params:
//   cidrs              CSV "10.0.0.0/24,192.168.1.0/24"  obrigatorio (>=1 cidr)
//   community          v2c
//   version            "v2c"|"v3" — default v2c
//   v3_user, v3_auth_proto, v3_auth_pass, v3_priv_proto, v3_priv_pass, v3_context
//   concurrency        inteiro (default 50)
//   per_host_timeout_ms inteiro (default 1000)
//   batch_sleep_ms     inteiro (default 50)
//   run_once           "true"|"false" — default false; quando true, segunda
//                      Run em diante e no-op (state via atomic.Bool).
//
// Wire de CIDRs do servidor: o backend Quarkus, ao montar CheckConfig
// para snmp.autodiscover, copia CollectorConfig.autodiscovery_cidrs (proto
// field 8) para params["cidrs"]. Isso mantem o Check interface livre de
// dependencia direta no Config global.
//
// Decisao arquitetural (canal global vs por-Runtime): documentada em
// events.go — singleton justifica-se enquanto so 1 check emite Events;
// refator quando outro chegar (Phase 4+).

package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/ispwatch/collector/internal/discovery"
)

// scanSNMPFn e o test seam — substituido nos tests para evitar abrir
// sockets UDP. Em prod aponta para discovery.ScanSNMP.
type scanSNMPFn func(ctx context.Context, cidrs []string, p discovery.ScanParams) ([]discovery.Candidate, error)

var scanSNMP scanSNMPFn = discovery.ScanSNMP

// snmpAutodiscoverCheck implementa Check pra snmp.autodiscover.
type snmpAutodiscoverCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string

	cidrs      []string
	scanParams discovery.ScanParams
	runOnce    bool
	done       atomic.Bool
}

func newSnmpAutodiscoverCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()

	rawCidrs := strings.TrimSpace(params["cidrs"])
	if rawCidrs == "" {
		return nil, fmt.Errorf("snmp.autodiscover: param 'cidrs' obrigatorio (CSV de CIDRs)")
	}
	parts := strings.Split(rawCidrs, ",")
	cidrs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cidrs = append(cidrs, p)
		}
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("snmp.autodiscover: param 'cidrs' parseado vazio")
	}

	version := strings.TrimSpace(params["version"])
	if version == "" {
		version = "v2c"
	}

	concurrency := atoiDefault(params["concurrency"], 50)
	perHostMs := atoiDefault(params["per_host_timeout_ms"], 1000)
	batchSleepMs := atoiDefault(params["batch_sleep_ms"], 50)

	scanParams := discovery.ScanParams{
		Version:        version,
		Community:      params["community"],
		V3User:         params["v3_user"],
		V3AuthProto:    params["v3_auth_proto"],
		V3AuthPass:     params["v3_auth_pass"],
		V3PrivProto:    params["v3_priv_proto"],
		V3PrivPass:     params["v3_priv_pass"],
		V3ContextName:  params["v3_context"],
		Concurrency:    concurrency,
		PerHostTimeout: time.Duration(perHostMs) * time.Millisecond,
		BatchSleep:     time.Duration(batchSleepMs) * time.Millisecond,
	}

	runOnce := strings.EqualFold(strings.TrimSpace(params["run_once"]), "true")

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		// Default 1h — scans nao sao realtime.
		interval = 1 * time.Hour
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "snmp.autodiscover-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &snmpAutodiscoverCheck{
		id:         id,
		interval:   interval,
		hostID:     cfg.GetHostId(),
		staticTags: tags,
		cidrs:      cidrs,
		scanParams: scanParams,
		runOnce:    runOnce,
	}, nil
}

func (c *snmpAutodiscoverCheck) ID() string              { return c.id }
func (c *snmpAutodiscoverCheck) Interval() time.Duration { return c.interval }
func (c *snmpAutodiscoverCheck) Tags() map[string]string { return c.staticTags }

// Run executa o scan e emite Events host.discovered no canal global.
// Nao emite Metrics — retorna (nil, nil) sempre, exceto em erro grave
// no scan (que e raro: discovery.ScanSNMP so retorna erro pra CIDR
// invalido na entrada, ja validado no factory).
func (c *snmpAutodiscoverCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if c.runOnce && c.done.Load() {
		return nil, nil
	}

	cands, err := scanSNMP(ctx, c.cidrs, c.scanParams)
	if err != nil {
		return nil, fmt.Errorf("snmp.autodiscover scan: %w", err)
	}

	if c.runOnce {
		c.done.Store(true)
	}

	if len(cands) == 0 {
		return nil, nil
	}

	events := make([]*collectorv1.Event, 0, len(cands))
	now := timestamppb.Now()
	for _, cand := range cands {
		details, err := structpb.NewStruct(map[string]interface{}{
			"sysobjectid":        cand.SysObjectID,
			"profile_suggestion": cand.ProfileSuggestion,
			"port":               float64(cand.Port),
		})
		if err != nil {
			continue
		}
		events = append(events, &collectorv1.Event{
			Time:      now,
			HostId:    cand.IP,
			EventType: "host.discovered",
			Severity:  "info",
			Details:   details,
		})
	}

	ch := EventsChannel()
	if ch == nil {
		// Canal nao instalado — silently drop. Acontece em bootstrap antes
		// do main wirar o transport, ou em testes sem channel.
		return nil, nil
	}
	select {
	case ch <- events:
	default:
		// Consumidor lento — descarta lote (Pitfall: nao bloquear o Runtime).
		// Plan 6 vai wirar drain via gRPC StreamEvents; log de drop fica
		// implícito no consumer (scheduler ja loga "channel full" em padrao).
	}
	return nil, nil
}

// atoiDefault parseia inteiro com fallback default.
func atoiDefault(raw string, def int) int {
	s := strings.TrimSpace(raw)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// init auto-registra a factory no Registry Default.
func init() {
	Default.Register("snmp.autodiscover", newSnmpAutodiscoverCheck)
}
