// redis_server_test.go — testes do check "redis.server" (Phase 4 Plan 07).
//
// Estratégia de teste:
//   - Metric/parsing coverage usa um fake `redisInfoFetcher` que retorna
//     fixtures fiéis ao output real de INFO (com seções memory/stats/
//     replication/clients/keyspace completas). miniredis v2.38 SÓ suporta
//     `INFO clients|stats` parciais — insuficiente pra cobrir o contrato
//     RESEARCH §Pattern 6. Deviation documentada no SUMMARY.
//   - Factory wiring usa miniredis pra garantir que o caminho de produção
//     (defaultRedisFetcherFactory → goredisFetcher → *goredis.Client)
//     conecta e Close() é benigno.
//
// Cobertura:
//   1. Factory rejeita addr ausente
//   2. Run() emite 7 métricas a partir de fixture realista (master)
//   3. Réplica (role=slave) calcula replication_lag_bytes > 0
//   4. static_tags propagam pra cada métrica + tag redis_role
//   5. Close() encerra fetcher; idempotente
//   6. Factory registrada em Default
//   7. Smoke: factory + Close contra miniredis real

package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// fakeRedisFetcher devolve INFO fixture estática. Permite parametrizar
// role / offsets / contadores nos testes.
type fakeRedisFetcher struct {
	info     string
	err      error
	closed   bool
	closeErr error
}

func (f *fakeRedisFetcher) Info(ctx context.Context, sections ...string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.info, nil
}

func (f *fakeRedisFetcher) Close() error {
	f.closed = true
	return f.closeErr
}

// infoMaster é fixture realista da saída de INFO em primário.
const infoMaster = `# Server
redis_version:7.4.0

# Clients
connected_clients:42
blocked_clients:0

# Memory
used_memory:104857600
used_memory_peak:209715200
mem_fragmentation_ratio:1.23

# Stats
instantaneous_ops_per_sec:1234
keyspace_hits:50000
keyspace_misses:1000

# Replication
role:master
master_repl_offset:1000000
connected_slaves:1

# Keyspace
db0:keys=1000,expires=500,avg_ttl=3600000
`

// infoReplica simula uma réplica com lag conhecido (1000000 − 999500 = 500).
const infoReplica = `# Clients
connected_clients:5

# Memory
used_memory:52428800
used_memory_peak:104857600

# Stats
instantaneous_ops_per_sec:100
keyspace_hits:10000
keyspace_misses:200

# Replication
role:slave
master_repl_offset:1000000
slave_repl_offset:999500
master_link_status:up
`

// newRedisServerWithFetcher cria um redisServer com fetcher fake injetado,
// pulando a Factory (que tentaria abrir conexão real). Usado pelos tests
// de parsing/emissão.
func newRedisServerWithFetcher(hostID string, staticTags map[string]string, f redisInfoFetcher) *redisServer {
	if staticTags == nil {
		staticTags = map[string]string{}
	}
	return &redisServer{
		id:         "redis.server-" + hostID,
		hostID:     hostID,
		addr:       "127.0.0.1:6379",
		interval:   30 * time.Second,
		staticTags: staticTags,
		fetcher:    f,
	}
}

// TestRedisServer_FactoryRejectsMissingAddr — addr é obrigatório.
func TestRedisServer_FactoryRejectsMissingAddr(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "redis.server",
		Interval:  durationpb.New(30 * time.Second),
		Enabled:   true,
		HostId:    "host-1",
		Params:    map[string]string{}, // sem addr
	}
	_, err := newRedisServerCheck(cfg)
	if err == nil {
		t.Fatal("expected error when addr is missing, got nil")
	}
	if !contains(err.Error(), "addr") {
		t.Errorf("error should mention 'addr', got %q", err.Error())
	}
}

// TestRedisServer_RunEmitsMetricsAgainstFixture — sanity end-to-end com
// fixture realista de INFO primário.
func TestRedisServer_RunEmitsMetricsAgainstFixture(t *testing.T) {
	rs := newRedisServerWithFetcher("host-1", nil, &fakeRedisFetcher{info: infoMaster})
	defer rs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := rs.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	expected := map[string]float64{
		"redis.used_memory":           104857600,
		"redis.used_memory_peak":      209715200,
		"redis.ops_per_sec":           1234,
		"redis.keyspace_hits":         50000,
		"redis.keyspace_misses":       1000,
		"redis.connected_clients":     42,
		"redis.replication_lag_bytes": 0, // master
	}
	seen := map[string]bool{}
	for _, m := range metrics {
		if m.Source != "redis.server" {
			t.Errorf("metric %q source=%q want redis.server", m.MetricName, m.Source)
		}
		if want, ok := expected[m.MetricName]; ok {
			if m.Value != want {
				t.Errorf("metric %q value=%v want %v", m.MetricName, m.Value, want)
			}
			seen[m.MetricName] = true
		}
		if m.Tags["redis_role"] != "master" {
			t.Errorf("metric %q redis_role=%q want master", m.MetricName, m.Tags["redis_role"])
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Errorf("missing metric %q (got %d total)", name, len(metrics))
		}
	}
}

// TestRedisServer_ReplicaComputesLag — role=slave com offsets ⇒ lag positivo.
func TestRedisServer_ReplicaComputesLag(t *testing.T) {
	rs := newRedisServerWithFetcher("host-rep", nil, &fakeRedisFetcher{info: infoReplica})
	defer rs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := rs.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var gotLag *float64
	for _, m := range metrics {
		if m.MetricName == "redis.replication_lag_bytes" {
			v := m.Value
			gotLag = &v
			if m.Tags["redis_role"] != "slave" {
				t.Errorf("redis_role=%q want slave", m.Tags["redis_role"])
			}
			break
		}
	}
	if gotLag == nil {
		t.Fatal("redis.replication_lag_bytes metric not found")
	}
	if *gotLag != 500 {
		t.Errorf("replication_lag_bytes=%v want 500", *gotLag)
	}
}

// TestRedisServer_PropagatesStaticTags — static_tags + redis_role coexistem
// em toda métrica emitida.
func TestRedisServer_PropagatesStaticTags(t *testing.T) {
	rs := newRedisServerWithFetcher("host-tags",
		map[string]string{"role": "redis", "env": "test"},
		&fakeRedisFetcher{info: infoMaster})
	defer rs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := rs.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics, got none")
	}

	for _, m := range metrics {
		if m.Tags["role"] != "redis" {
			t.Errorf("metric %q tags[role]=%q want redis", m.MetricName, m.Tags["role"])
		}
		if m.Tags["env"] != "test" {
			t.Errorf("metric %q tags[env]=%q want test", m.MetricName, m.Tags["env"])
		}
		if m.Tags["redis_role"] == "" {
			t.Errorf("metric %q missing tag redis_role", m.MetricName)
		}
	}
}

// TestRedisServer_RunPropagatesError — fetcher.Info erro vira erro de Run
// envolto com a addr (sem leak de auth no message).
func TestRedisServer_RunPropagatesError(t *testing.T) {
	fakeErr := errors.New("connection refused")
	rs := newRedisServerWithFetcher("host-err", nil, &fakeRedisFetcher{err: fakeErr})
	defer rs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := rs.Run(ctx)
	if err == nil {
		t.Fatal("expected Run to return error from fetcher")
	}
	if !contains(err.Error(), "redis.server") {
		t.Errorf("error should prefix with 'redis.server', got %q", err.Error())
	}
	if contains(err.Error(), "password") || contains(err.Error(), "auth") {
		t.Errorf("error message must not contain auth/password, got %q", err.Error())
	}
}

// TestRedisServer_CloseShutsDownFetcher — Close() libera fetcher; segunda
// chamada é benigna (idempotente).
func TestRedisServer_CloseShutsDownFetcher(t *testing.T) {
	f := &fakeRedisFetcher{info: infoMaster}
	rs := newRedisServerWithFetcher("host-close", nil, f)
	if err := rs.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if !f.closed {
		t.Error("fetcher.Close was not called")
	}
	// idempotência: segundo Close não panica nem retorna erro.
	if err := rs.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestRedisServer_Registry — confirma init() registrou em Default.
func TestRedisServer_Registry(t *testing.T) {
	f, ok := Default.Get("redis.server")
	if !ok {
		t.Fatal("redis.server not registered in Default")
	}
	if f == nil {
		t.Fatal("registered factory is nil")
	}
}

// TestRedisServer_FactorySmokeAgainstMiniredis — caminho de produção end-
// to-end: defaultRedisFetcherFactory cria *goredis.Client, miniredis
// responde a Close. Não tenta INFO (limitação documentada da miniredis).
func TestRedisServer_FactorySmokeAgainstMiniredis(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	cfg := &collectorv1.CheckConfig{
		CheckId:   "redis-smoke",
		CheckType: "redis.server",
		Interval:  durationpb.New(30 * time.Second),
		HostId:    "host-smoke",
		Params:    map[string]string{"addr": mr.Addr()},
	}
	c, err := newRedisServerCheck(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	rs := c.(*redisServer)
	if rs.fetcher == nil {
		t.Fatal("factory did not wire fetcher")
	}
	if err := rs.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
