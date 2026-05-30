package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// stubRow implementa pgx.Row em memória — substitui pgxpool.QueryRow nos
// unit tests sem depender de Postgres real.
type stubRow struct {
	vals []any
	err  error
}

func (r *stubRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.vals) {
		return errors.New("stubRow: dest count mismatch")
	}
	for i, d := range dest {
		switch v := d.(type) {
		case *int64:
			*v = r.vals[i].(int64)
		case *float64:
			*v = r.vals[i].(float64)
		default:
			return errors.New("stubRow: unsupported dest type")
		}
	}
	return nil
}

// stubPgxPool implementa pgxPool em memória.
type stubPgxPool struct {
	pingErr  error
	rowsBySQLPrefix map[string]*stubRow // chave: prefixo da SQL (primeiros 40 chars)
	defaultRow      *stubRow
	queries         []string
	closed          bool
}

func (p *stubPgxPool) Ping(ctx context.Context) error { return p.pingErr }
func (p *stubPgxPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	p.queries = append(p.queries, sql)
	for prefix, row := range p.rowsBySQLPrefix {
		if strings.Contains(sql, prefix) {
			return row
		}
	}
	if p.defaultRow != nil {
		return p.defaultRow
	}
	return &stubRow{err: errors.New("stubPgxPool: no row for sql")}
}
func (p *stubPgxPool) Close() { p.closed = true }

func newStubPgxPool() *stubPgxPool {
	return &stubPgxPool{
		rowsBySQLPrefix: map[string]*stubRow{
			"state = 'active'":             {vals: []any{int64(5)}},
			"idle in transaction":          {vals: []any{int64(2)}},
			"query_start <":                {vals: []any{int64(1)}},
			"pg_last_xact_replay_timestamp": {vals: []any{float64(0.5)}},
			"pg_wal_lsn_diff":              {vals: []any{int64(1024)}},
			"last_autovacuum":              {vals: []any{int64(3)}},
		},
	}
}

// stubPoolFactory: substitui pgxpool.NewWithConfig em test pra retornar
// stub sem TCP/DNS.
func newStubPoolFactory(p pgxPool, err error) pgxPoolFactory {
	return func(ctx context.Context, dsn string) (pgxPool, error) {
		if err != nil {
			return nil, err
		}
		return p, nil
	}
}

func TestPostgresServer_FactoryRejectsMissingDsn(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.server",
		Interval:  durationpb.New(60 * time.Second),
		HostId:    "host-1",
		Params:    map[string]string{},
	}
	_, err := newPostgresServerCheck(cfg)
	if err == nil {
		t.Fatal("expected error for missing dsn")
	}
	if !strings.Contains(err.Error(), "dsn") {
		t.Errorf("expected error to mention 'dsn'; got %v", err)
	}
}

func TestPostgresServer_FactoryRejectsBadDsn(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.server",
		Interval:  durationpb.New(60 * time.Second),
		HostId:    "host-1",
		Params:    map[string]string{"dsn": "::::not-a-dsn::::"},
	}
	_, err := newPostgresServerCheckWithFactory(cfg, defaultPgxPoolFactory)
	if err == nil {
		t.Fatal("expected error for bad dsn")
	}
	if !strings.Contains(err.Error(), "DSN inválido") {
		t.Errorf("expected error to contain 'DSN inválido'; got %v", err)
	}
}

func TestPostgresServer_FactoryClosesPoolOnPingFail(t *testing.T) {
	stub := &stubPgxPool{pingErr: errors.New("connection refused")}
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.server",
		HostId:    "host-1",
		Params:    map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	_, err := newPostgresServerCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err == nil {
		t.Fatal("expected error for ping fail")
	}
	if !stub.closed {
		t.Error("expected pool.Close() to be called on Ping fail (Pitfall 5)")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("expected error to mention 'unreachable'; got %v", err)
	}
}

func TestPostgresServer_RunEmitsAllMetrics(t *testing.T) {
	stub := newStubPgxPool()
	cfg := &collectorv1.CheckConfig{
		CheckId:   "pg-1",
		CheckType: "postgres.server",
		Interval:  durationpb.New(60 * time.Second),
		HostId:    "host-1",
		Params:    map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	c, err := newPostgresServerCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}

	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned err: %v", err)
	}
	if len(metrics) < 6 {
		t.Fatalf("expected >=6 metrics; got %d", len(metrics))
	}

	wantNames := map[string]bool{
		"postgres.active_connections":     false,
		"postgres.idle_in_transaction":    false,
		"postgres.slow_queries":           false,
		"postgres.replication_lag_seconds": false,
		"postgres.wal_lag_bytes":          false,
		"postgres.vacuum_stale_tables":    false,
	}
	for _, m := range metrics {
		if _, ok := wantNames[m.MetricName]; ok {
			wantNames[m.MetricName] = true
		}
		if m.Source != "postgres.server" {
			t.Errorf("metric %q: expected Source=postgres.server; got %q", m.MetricName, m.Source)
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("expected metric %q to be emitted", name)
		}
	}
}

func TestPostgresServer_TagsMergeStaticTags(t *testing.T) {
	stub := newStubPgxPool()
	cfg := &collectorv1.CheckConfig{
		CheckType:  "postgres.server",
		HostId:     "host-1",
		StaticTags: map[string]string{"role": "postgres", "env": "prod"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	c, err := newPostgresServerCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	metrics, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("no metrics emitted")
	}
	for _, m := range metrics {
		if m.Tags["role"] != "postgres" {
			t.Errorf("metric %q: expected tag role=postgres; got %v", m.MetricName, m.Tags)
		}
		if m.Tags["env"] != "prod" {
			t.Errorf("metric %q: expected tag env=prod; got %v", m.MetricName, m.Tags)
		}
	}
}

func TestPostgresServer_CloseReleasesPool(t *testing.T) {
	stub := newStubPgxPool()
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.server",
		HostId:    "host-1",
		Params:    map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	c, err := newPostgresServerCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	closer, ok := c.(interface{ Close() error })
	if !ok {
		t.Fatal("postgresServer must implement Close() error")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("Close returned err: %v", err)
	}
	if !stub.closed {
		t.Error("expected pool.Close() to be called by Check.Close()")
	}
}

func TestPostgresServer_RegisteredInDefaultRegistry(t *testing.T) {
	if _, ok := Default.Get("postgres.server"); !ok {
		t.Fatal("postgres.server must be registered in Default registry via init()")
	}
}

func TestPostgresServer_IDDefaultsFromHostID(t *testing.T) {
	stub := newStubPgxPool()
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.server",
		HostId:    "host-99",
		Params:    map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	c, err := newPostgresServerCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	if c.ID() != "postgres.server-host-99" {
		t.Errorf("expected default ID=postgres.server-host-99; got %q", c.ID())
	}
	if c.Interval() != 60*time.Second {
		t.Errorf("expected default Interval=60s; got %v", c.Interval())
	}
}
