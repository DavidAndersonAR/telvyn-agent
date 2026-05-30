package config

import (
	"os"
	"path/filepath"
	"testing"
)

// makeCertFiles creates dummy cert/key/ca files in dir so Parse can validate
// they are readable — Parse checks os.Stat on cert files.
func makeCertFiles(t *testing.T) (cert, key, ca string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		return p
	}
	return write("cert.pem", "cert"), write("key.pem", "key"), write("ca.pem", "ca")
}

// TestConfig_WALFlags verifies that --wal-path and --wal-max-mb are parsed
// and that WalMaxBytes is correctly derived from WalMaxMb * 1024 * 1024.
func TestConfig_WALFlags(t *testing.T) {
	cert, key, ca := makeCertFiles(t)

	cfg, err := Parse([]string{
		"--tenant-id=tenant1",
		"--collector-id=col1",
		"--server=localhost:8443",
		"--client-cert=" + cert,
		"--client-key=" + key,
		"--trust-bundle=" + ca,
		"--wal-path=/tmp/custom-wal.db",
		"--wal-max-mb=512",
	})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.WalPath != "/tmp/custom-wal.db" {
		t.Errorf("WalPath: expected /tmp/custom-wal.db, got %q", cfg.WalPath)
	}
	want := int64(512) * 1024 * 1024
	if cfg.WalMaxBytes != want {
		t.Errorf("WalMaxBytes: expected %d, got %d", want, cfg.WalMaxBytes)
	}
}

// TestResolveTaggerBudget cobre o helper que carrega o budget do
// CollectorConfig (proto field 7) com fallback ao default quando o servidor
// não setou nada. Tabela: zero → default; positivo → preserva.
func TestResolveTaggerBudget(t *testing.T) {
	cases := []struct {
		name   string
		input  int32
		expect int
	}{
		{"zero falls back to default", 0, DefaultTaggerBudget},
		{"negative falls back to default", -1, DefaultTaggerBudget},
		{"small budget preserved", 500, 500},
		{"large budget preserved", 50000, 50000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveTaggerBudget(c.input)
			if got != c.expect {
				t.Errorf("ResolveTaggerBudget(%d): got %d, want %d", c.input, got, c.expect)
			}
		})
	}
}

// TestConfig_WALDefaults verifies that WAL flags have sensible defaults when
// not explicitly set.
func TestConfig_WALDefaults(t *testing.T) {
	cert, key, ca := makeCertFiles(t)

	cfg, err := Parse([]string{
		"--tenant-id=t", "--collector-id=c", "--server=h:1",
		"--client-cert=" + cert,
		"--client-key=" + key,
		"--trust-bundle=" + ca,
	})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.WalPath == "" {
		t.Error("WalPath should not be empty (default path must be set)")
	}
	if cfg.WalMaxBytes != int64(1024)*1024*1024 {
		t.Errorf("default WalMaxBytes should be 1GB, got %d", cfg.WalMaxBytes)
	}
	// Span WAL + config cache defaults (Tasks 1 & 2).
	if cfg.SpanWalPath == "" {
		t.Error("SpanWalPath should not be empty (default path must be set)")
	}
	if cfg.SpanWalMaxBytes != int64(512)*1024*1024 {
		t.Errorf("default SpanWalMaxBytes should be 512MB, got %d", cfg.SpanWalMaxBytes)
	}
	if cfg.ConfigCachePath == "" {
		t.Error("ConfigCachePath should not be empty (default path must be set)")
	}
}

// TestConfig_SpanWALFlags verifies the span WAL flags parse and derive bytes.
func TestConfig_SpanWALFlags(t *testing.T) {
	cert, key, ca := makeCertFiles(t)
	cfg, err := Parse([]string{
		"--tenant-id=t", "--collector-id=c", "--server=h:1",
		"--client-cert=" + cert, "--client-key=" + key, "--trust-bundle=" + ca,
		"--span-wal-path=/tmp/custom-spans.db",
		"--span-wal-max-mb=256",
		"--config-cache-path=/tmp/custom-cache.pb",
	})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.SpanWalPath != "/tmp/custom-spans.db" {
		t.Errorf("SpanWalPath: got %q", cfg.SpanWalPath)
	}
	if cfg.SpanWalMaxBytes != int64(256)*1024*1024 {
		t.Errorf("SpanWalMaxBytes: got %d", cfg.SpanWalMaxBytes)
	}
	if cfg.ConfigCachePath != "/tmp/custom-cache.pb" {
		t.Errorf("ConfigCachePath: got %q", cfg.ConfigCachePath)
	}
}

// TestConfig_WALCapEnvOverride verifies env vars size the WAL caps for
// multi-hour outages without a flag (Task 3), and that an explicit flag wins
// over the env.
func TestConfig_WALCapEnvOverride(t *testing.T) {
	cert, key, ca := makeCertFiles(t)
	base := []string{
		"--tenant-id=t", "--collector-id=c", "--server=h:1",
		"--client-cert=" + cert, "--client-key=" + key, "--trust-bundle=" + ca,
	}

	t.Run("env applies when flag at default", func(t *testing.T) {
		t.Setenv("ISPWATCH_WAL_MAX_MB", "8192")
		t.Setenv("ISPWATCH_SPAN_WAL_MAX_MB", "4096")
		cfg, err := Parse(base)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if cfg.WalMaxBytes != int64(8192)*1024*1024 {
			t.Errorf("WalMaxBytes from env: got %d", cfg.WalMaxBytes)
		}
		if cfg.SpanWalMaxBytes != int64(4096)*1024*1024 {
			t.Errorf("SpanWalMaxBytes from env: got %d", cfg.SpanWalMaxBytes)
		}
	})

	t.Run("explicit flag overrides env", func(t *testing.T) {
		t.Setenv("ISPWATCH_WAL_MAX_MB", "8192")
		cfg, err := Parse(append(append([]string{}, base...), "--wal-max-mb=2048"))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if cfg.WalMaxBytes != int64(2048)*1024*1024 {
			t.Errorf("explicit flag should win over env: got %d", cfg.WalMaxBytes)
		}
	})
}
