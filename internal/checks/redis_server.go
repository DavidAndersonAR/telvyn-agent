// redis_server.go — Check "redis.server" (Phase 4 Plan 07).
//
// Coleta métricas de saúde de uma instância Redis via comando INFO,
// emitindo 7 métricas por ciclo:
//   - redis.used_memory / redis.used_memory_peak  (bytes)
//   - redis.ops_per_sec                           (instantaneous)
//   - redis.keyspace_hits / redis.keyspace_misses (counters)
//   - redis.connected_clients
//   - redis.replication_lag_bytes  (master_repl_offset − slave_repl_offset
//                                   se role=slave; 0 quando primário)
//
// Toda métrica carrega tag `redis_role` (master/slave) além dos static_tags
// do CheckConfig. Source = "redis.server".
//
// Decisões locked:
//   - INFO é abstraído via `redisInfoFetcher` interface — em prod aponta para
//     o cliente go-redis real; em testes usa fake fixture-driven (miniredis
//     v2.38 não suporta INFO multi-section nem todos os campos que
//     Phase 4 RESEARCH §Pattern 6 documenta).
//   - Cliente único reusado entre Runs; go-redis pool interno cuida do
//     reconnect; sem ping no factory pra não falhar Reload do CheckConfig
//     quando o Redis estiver temporariamente down.
//   - Parser tolerante: ignora linhas vazias e comentários (`# ...`); cada
//     section header (`# Replication`) é skip silencioso. Valores não-numéricos
//     simplesmente não viram métrica (sem erro), exceto `role` que vira tag.
//   - Replication lag exige role=="slave" + ambos offsets parseados; caso
//     contrário emite 0 (primário ou estado transiente).
//
// Threat note: o param `auth` chega plaintext do Quarkus (decifrado in-flight
// pós-Phase 4 D-10). Erros do go-redis usam só addr no message — sem leak
// de password (validado em TestRedisServer_FactoryRejectsMissingAddr).

package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultRedisInterval    = 30 * time.Second
	defaultRedisDialTimeout = 3 * time.Second
	defaultRedisReadTimeout = 5 * time.Second
)

// redisInfoFetcher abstrai a coleta de INFO. Em prod é um *goredis.Client;
// em testes é fake que retorna fixture estática. Esse seam existe porque
// miniredis (v2.38) só suporta `INFO clients|stats` parciais — sem campos
// memory/replication/keyspace que RESEARCH §Pattern 6 contractualmente
// documenta.
type redisInfoFetcher interface {
	Info(ctx context.Context, sections ...string) (string, error)
	Close() error
}

// goredisFetcher embrulha *goredis.Client cumprindo redisInfoFetcher.
type goredisFetcher struct {
	client *goredis.Client
}

func (g *goredisFetcher) Info(ctx context.Context, sections ...string) (string, error) {
	return g.client.Info(ctx, sections...).Result()
}

func (g *goredisFetcher) Close() error {
	if g.client == nil {
		return nil
	}
	return g.client.Close()
}

// redisFetcherFactory permite o test injetar um fake fetcher; em prod
// constrói o *goredis.Client real a partir do addr+auth.
type redisFetcherFactory func(addr, auth string) redisInfoFetcher

var defaultRedisFetcherFactory redisFetcherFactory = func(addr, auth string) redisInfoFetcher {
	c := goredis.NewClient(&goredis.Options{
		Addr:        addr,
		Password:    auth,
		DialTimeout: defaultRedisDialTimeout,
		ReadTimeout: defaultRedisReadTimeout,
	})
	return &goredisFetcher{client: c}
}

// redisServer é a implementação concreta de Check para "redis.server".
type redisServer struct {
	id         string
	hostID     string
	addr       string
	auth       string
	interval   time.Duration
	staticTags map[string]string
	fetcher    redisInfoFetcher
}

// newRedisServerCheck é a Factory registrada em init() para "redis.server".
// Valida `addr` (obrigatório), aceita `auth` opcional. NÃO faz Ping —
// Redis temporariamente down não deve falhar Reload do CheckConfig.
func newRedisServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	addr := strings.TrimSpace(params["addr"])
	if addr == "" {
		return nil, fmt.Errorf("redis.server: missing param 'addr' (expected host:port)")
	}
	auth := params["auth"] // vazio = sem AUTH

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultRedisInterval
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "redis.server-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &redisServer{
		id:         id,
		hostID:     cfg.GetHostId(),
		addr:       addr,
		auth:       auth,
		interval:   interval,
		staticTags: tags,
		fetcher:    defaultRedisFetcherFactory(addr, auth),
	}, nil
}

func (r *redisServer) ID() string              { return r.id }
func (r *redisServer) Interval() time.Duration { return r.interval }
func (r *redisServer) Tags() map[string]string { return r.staticTags }

// Run executa um ciclo: roda INFO (5 seções), parseia, emite 7 métricas.
// Erro de RTT/conexão propaga; parse silenciosamente ignora linhas
// inválidas — é melhor emitir métricas parciais que falhar a Run inteira.
func (r *redisServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if r.fetcher == nil {
		return nil, fmt.Errorf("redis.server: fetcher closed")
	}
	infoStr, err := r.fetcher.Info(ctx,
		"replication", "memory", "stats", "clients", "keyspace")
	if err != nil {
		return nil, fmt.Errorf("redis.server: INFO %q: %w", r.addr, err)
	}

	parsed := parseRedisInfo(infoStr)
	role := parsed["role"]
	if role == "" {
		role = "unknown"
	}

	now := timestamppb.Now()
	extraTags := map[string]string{"redis_role": role}

	out := make([]*collectorv1.Metric, 0, 7)
	add := func(name, key string) {
		if v, ok := parseFloat(parsed[key]); ok {
			out = append(out, r.metric(now, name, v, extraTags))
		}
	}
	add("redis.used_memory", "used_memory")
	add("redis.used_memory_peak", "used_memory_peak")
	add("redis.ops_per_sec", "instantaneous_ops_per_sec")
	add("redis.keyspace_hits", "keyspace_hits")
	add("redis.keyspace_misses", "keyspace_misses")
	add("redis.connected_clients", "connected_clients")

	// replication_lag_bytes: só é positivo em réplica com ambos offsets;
	// caso contrário emite 0 (primário ou estado transiente).
	lag := 0.0
	if role == "slave" {
		mOff, mok := parseFloat(parsed["master_repl_offset"])
		sOff, sok := parseFloat(parsed["slave_repl_offset"])
		if mok && sok && mOff >= sOff {
			lag = mOff - sOff
		}
	}
	out = append(out, r.metric(now, "redis.replication_lag_bytes", lag, extraTags))

	return out, nil
}

// Close libera o fetcher subjacente. Idempotente — segundo Close é no-op.
func (r *redisServer) Close() error {
	if r.fetcher == nil {
		return nil
	}
	err := r.fetcher.Close()
	r.fetcher = nil
	return err
}

// parseRedisInfo quebra a saída de INFO em map[campo]valor. Linhas vazias
// e comentários (`# ...`) são puladas; cada linha "key:value" vira entry.
func parseRedisInfo(info string) map[string]string {
	out := make(map[string]string, 64)
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out
}

// parseFloat é parser leniente — string vazia retorna ok=false sem erro.
func parseFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// metric merge static_tags + extra (extra ganha em conflito) e produz Metric.
func (r *redisServer) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(r.staticTags)+len(extraTags))
	for k, v := range r.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     r.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "redis.server",
	}
}

// init auto-registra o factory em Default. Pattern datadog-agent — cada
// package de check se auto-anuncia; o binário só faz blank-import.
func init() {
	Default.Register("redis.server", newRedisServerCheck)
}
