// Package config holds the runtime configuration parsed from CLI flags.
// Env vars are intentionally NOT supported here — the daemon is launched
// by Pulumi/Ansible with explicit flags so the config surface is auditable.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	TenantID    string
	CollectorID string
	Server      string
	ClientCert  string
	ClientKey   string
	TrustBundle string
	LogLevel    string

	// Phase 5 — tuning (collector.conf). Pode vir do arquivo, dos flags
	// CLI ou env. Flags > env > arquivo > defaults.
	ConfigFile         string        // path do collector.conf
	ConfigPollSeconds  int           // intervalo do pull config (default 10)
	SNMPPollers        int           // workers paralelos pra snmp.* (default 20)
	ICMPPingers        int           // workers paralelos pra icmp.* (default 5)
	CheckJitterMs      int           // jitter máximo no ticker dos checks (default 1000)
	BatchSize          int           // max metrics por batch (default 500)
	FlushSeconds       int           // flush periódico do producer (default 5)
	// Deprecated em Phase 5b — auth do pull-config virou mTLS (reaproveita
	// ClientCert/ClientKey/TrustBundle). Campo mantido pra compat de import,
	// mas a flag -agent-token e o env AGENT_TOKEN foram removidos.
	AgentToken         string

	// LLDP topology discovery (Phase 2). Bootstrap-style: enable via flags
	// while the server-driven discovery config doesn't exist yet. Targets
	// format: "host_id@address,host_id@address" — host_id is the inventory
	// reference at the server, address is "host" or "host:port" for SNMP.
	LldpTargets   string        // CSV of "host_id@address"
	LldpCommunity string        // SNMPv2c community
	LldpInterval  time.Duration // 0 = disabled
	LldpTimeout   time.Duration // per-target SNMP deadline

	// WAL (write-ahead log) configuration (Plan 5, D-06 always-on).
	// WalPath is the bbolt file path; WalMaxBytes is the soft cap (D-05).
	WalPath     string
	WalMaxBytes int64

	// Span WAL configuration (Task 1, trace durability). Separate bbolt file
	// + independent byte cap so a span flood can't eat the metrics WAL budget.
	// SpanWalPath defaults next to WalPath; SpanWalMaxBytes is the soft cap.
	SpanWalPath     string
	SpanWalMaxBytes int64

	// ConfigCachePath is where the last-known-good server config is persisted
	// so the collector keeps polling its last jobs across a backend restart or
	// a multi-hour POP isolation (Task 2). Defaults next to WalPath.
	ConfigCachePath string
}

// tuningDefaults dá os valores padrão pra options performance-related.
//
// Calibrados pra ~500-1000 hosts numa máquina pequena/média (4 CPU, 4G RAM).
// Acima de 1000 hosts ou em hardware menor, ajustar via collector.conf — ver
// TUNING.md no diretório do agent pra guidelines.
//
//   - poll=15s    → server query é leve (~ms), 15s mantém staleness baixa
//                   sem martelar; raise pra 30-60s se config muda pouco
//   - snmp=50     → walks pesados costumam levar 2-5s; 50 paralelos sustentam
//                   ~750-1500 walks/min, cobrindo 1000 hosts em 60s budget
//   - icmp=20     → ping é leve (sub-segundo); 20 paralelos cobrem >3k hosts
//   - jitter=10s  → reduz pico de "todos começam juntos" pra hosts criados em
//                   ondas. 10s espalha 1000 checks em batches de ~100/seg
//   - batch=1000  → metrics por gRPC batch; >1000 começa a inchar payload
//   - flush=5s    → janela de latência aceitável entre coleta e backend
func tuningDefaults() (poll, snmp, icmp, jitter, batch, flush int) {
	return 15, 50, 20, 10000, 1000, 5
}

// Phase 3 Plan 05 — autodiscovery_cidrs (proto field 8) chega via
// CollectorConfig do servidor, não via CLI flag. A normalização/dedup
// vive em autodiscovery.go: helper AutodiscoveryCIDRs. Documentado aqui
// pra contexto de quem lê config.go primeiro.

// LldpEnabled reports whether the LLDP discovery runner should start.
func (c *Config) LldpEnabled() bool {
	return c.LldpInterval > 0 && strings.TrimSpace(c.LldpTargets) != ""
}

// ParseLldpTargets splits the CSV form "host_id@address" into a list ready
// for the runner. Entries with malformed shape (no '@') are skipped silently
// so a single typo doesn't take down the whole runner — invalid entries are
// caller-logged.
func (c *Config) ParseLldpTargets() []ParsedLldpTarget {
	out := make([]ParsedLldpTarget, 0)
	for _, raw := range strings.Split(c.LldpTargets, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "@", 2)
		if len(parts) != 2 {
			continue
		}
		hostId := strings.TrimSpace(parts[0])
		addr := strings.TrimSpace(parts[1])
		if hostId == "" || addr == "" {
			continue
		}
		out = append(out, ParsedLldpTarget{HostId: hostId, Address: addr})
	}
	return out
}

// ParsedLldpTarget é o resultado de ParseLldpTargets — uma entrada limpa.
type ParsedLldpTarget struct {
	HostId  string
	Address string
}

func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("collector", flag.ContinueOnError)
	c := &Config{}

	fs.StringVar(&c.TenantID, "tenant-id", "", "Tenant slug (must match cert CN)")
	fs.StringVar(&c.CollectorID, "collector-id", "", "Collector instance UUID/slug (must match cert OU)")
	fs.StringVar(&c.Server, "server", "", "Central gRPC endpoint host:port (e.g. collector.ispwatch.io:8443)")
	fs.StringVar(&c.ClientCert, "client-cert", "", "Path to client cert fullchain (PEM)")
	fs.StringVar(&c.ClientKey, "client-key", "", "Path to client private key (PEM)")
	fs.StringVar(&c.TrustBundle, "trust-bundle", "", "Path to CA bundle that signed the server cert (PEM)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "debug|info|warn|error")

	// LLDP topology discovery (Phase 2)
	fs.StringVar(&c.LldpTargets, "lldp-targets", "", "Comma-separated host_id@address[:port] entries to discover via LLDP. Empty disables.")
	fs.StringVar(&c.LldpCommunity, "lldp-community", "public", "SNMPv2c community used for LLDP polling")
	fs.DurationVar(&c.LldpInterval, "lldp-interval", 0, "How often to walk LLDP-MIB on each target. 0 disables (default).")
	fs.DurationVar(&c.LldpTimeout, "lldp-timeout", 5*time.Second, "Per-target SNMP deadline")

	// WAL (write-ahead log) flags (Plan 5, D-06 always-on).
	// Default path follows platform conventions (same as datadog-agent state dir).
	defaultWalPath := "./wal.db"
	if runtime.GOOS == "linux" {
		defaultWalPath = "/var/lib/ispwatch-collector/wal.db"
	} else if runtime.GOOS == "windows" {
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			defaultWalPath = pd + `\IspWatch\wal.db`
		}
	}
	var walMaxMb, spanWalMaxMb int
	fs.StringVar(&c.WalPath, "wal-path", defaultWalPath, "Path to the WAL bbolt file (persists metrics across restarts)")
	fs.IntVar(&walMaxMb, "wal-max-mb", 1024, "Metrics WAL soft cap in MB — oldest entries dropped first when exceeded (D-05). Env: ISPWATCH_WAL_MAX_MB")

	// Span WAL + config cache (Tasks 1 & 2). Paths derive from WalPath's
	// directory by default so a single -wal-path move relocates all state.
	walDir := filepath.Dir(defaultWalPath)
	defaultSpanWalPath := filepath.Join(walDir, "spans.db")
	defaultConfigCachePath := filepath.Join(walDir, "config-cache.pb")
	fs.StringVar(&c.SpanWalPath, "span-wal-path", defaultSpanWalPath, "Path to the span WAL bbolt file (persists traces across restarts/outages)")
	fs.IntVar(&spanWalMaxMb, "span-wal-max-mb", 512, "Span WAL soft cap in MB — oldest entries dropped first when exceeded. Env: ISPWATCH_SPAN_WAL_MAX_MB")
	fs.StringVar(&c.ConfigCachePath, "config-cache-path", defaultConfigCachePath, "Path to the last-known-good server config cache (keeps jobs running across backend restart)")

	// Phase 5 — performance tuning.
	defPoll, defSnmp, defIcmp, defJitter, defBatch, defFlush := tuningDefaults()
	fs.StringVar(&c.ConfigFile, "config-file", "", "Path to collector.conf (key=value file). CLI flags override file values.")
	fs.IntVar(&c.ConfigPollSeconds, "config-poll-seconds", defPoll,    "How often to poll server for config delta (seconds)")
	fs.IntVar(&c.SNMPPollers,       "snmp-pollers",        defSnmp,    "Parallel workers for snmp.* checks")
	fs.IntVar(&c.ICMPPingers,       "icmp-pingers",        defIcmp,    "Parallel workers for icmp.* checks")
	fs.IntVar(&c.CheckJitterMs,     "check-jitter-ms",     defJitter,  "Random jitter (0..N ms) added to each check ticker start")
	fs.IntVar(&c.BatchSize,         "batch-size",          defBatch,   "Max metrics per batch (producer flushes when reached)")
	fs.IntVar(&c.FlushSeconds,      "flush-seconds",       defFlush,   "Periodic producer flush (seconds) — fires before batch fills")
	// Phase 5b: -agent-token / env AGENT_TOKEN removidos. Auth do pull-config
	// passou a usar mTLS reaproveitando ClientCert/ClientKey/TrustBundle.

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Env overrides for WAL caps (Task 3 — sized for multi-hour outages via
	// env without redeploying flags). Precedence: explicit flag > env >
	// default. We detect "flag left at default" by value comparison (same
	// tradeoff the collector.conf loader already makes below) and only then
	// apply the env value.
	if walMaxMb == 1024 {
		if v, ok := envInt("ISPWATCH_WAL_MAX_MB"); ok {
			walMaxMb = v
		}
	}
	if spanWalMaxMb == 512 {
		if v, ok := envInt("ISPWATCH_SPAN_WAL_MAX_MB"); ok {
			spanWalMaxMb = v
		}
	}
	if v := os.Getenv("ISPWATCH_SPAN_WAL_PATH"); v != "" && c.SpanWalPath == defaultSpanWalPath {
		c.SpanWalPath = v
	}
	if v := os.Getenv("ISPWATCH_CONFIG_CACHE_PATH"); v != "" && c.ConfigCachePath == defaultConfigCachePath {
		c.ConfigCachePath = v
	}

	c.WalMaxBytes = int64(walMaxMb) * 1024 * 1024
	c.SpanWalMaxBytes = int64(spanWalMaxMb) * 1024 * 1024

	// Carrega collector.conf se especificado. Arquivo NÃO sobrescreve flags
	// que o operador passou explicitamente — apenas preenche o que ficou
	// no default. (Implementação: detecta defaults e troca por valor do
	// arquivo; flags com mesmo valor que default são consideradas "não
	// fornecidas" — tradeoff aceito pra evitar reflexão sobre o flag set.)
	if c.ConfigFile != "" {
		if err := c.loadConfigFile(c.ConfigFile); err != nil {
			return nil, fmt.Errorf("config-file %s: %w", c.ConfigFile, err)
		}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadConfigFile faz parse simples de KEY=VALUE (ignorando # comentários e
// linhas em branco). Chaves reconhecidas mapeiam pros campos de tuning.
// Valores no arquivo só são aplicados quando o campo correspondente está
// no default — assim flags CLI continuam tendo precedência.
func (c *Config) loadConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defPoll, defSnmp, defIcmp, defJitter, defBatch, defFlush := tuningDefaults()
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Quote-stripping conveniência: aceitar 'foo' e "foo"
		if len(val) >= 2 {
			first, last := val[0], val[len(val)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		switch strings.ToLower(key) {
		case "configpollseconds":
			if c.ConfigPollSeconds == defPoll {
				if n, err := strconvAtoi(val); err == nil { c.ConfigPollSeconds = n }
			}
		case "snmppollers":
			if c.SNMPPollers == defSnmp {
				if n, err := strconvAtoi(val); err == nil { c.SNMPPollers = n }
			}
		case "icmppingers":
			if c.ICMPPingers == defIcmp {
				if n, err := strconvAtoi(val); err == nil { c.ICMPPingers = n }
			}
		case "checkjitterms":
			if c.CheckJitterMs == defJitter {
				if n, err := strconvAtoi(val); err == nil { c.CheckJitterMs = n }
			}
		case "batchsize":
			if c.BatchSize == defBatch {
				if n, err := strconvAtoi(val); err == nil { c.BatchSize = n }
			}
		case "flushseconds":
			if c.FlushSeconds == defFlush {
				if n, err := strconvAtoi(val); err == nil { c.FlushSeconds = n }
			}
		case "loglevel":
			if c.LogLevel == "info" { c.LogLevel = val }
		case "walpath":
			if c.WalPath != "" && (c.WalPath == "./wal.db" || strings.HasSuffix(c.WalPath, "wal.db")) {
				c.WalPath = val
			}
		case "walmaxmb":
			if n, err := strconvAtoi(val); err == nil && c.WalMaxBytes == 1024*1024*1024 {
				c.WalMaxBytes = int64(n) * 1024 * 1024
			}
		}
	}
	return nil
}

// envInt reads key from the environment and parses it as an int. Returns
// (0, false) when unset or unparseable so callers fall back to the default.
func envInt(key string) (int, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	n, err := strconvAtoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// strconvAtoi — local helper pra evitar import extra.
func strconvAtoi(s string) (int, error) {
	n := 0
	if s == "" { return 0, fmt.Errorf("empty") }
	neg := false
	i := 0
	if s[0] == '-' { neg = true; i = 1 }
	if s[0] == '+' { i = 1 }
	if i >= len(s) { return 0, fmt.Errorf("invalid") }
	for ; i < len(s); i++ {
		ch := s[i]
		if ch < '0' || ch > '9' { return 0, fmt.Errorf("invalid char %c", ch) }
		n = n*10 + int(ch-'0')
	}
	if neg { n = -n }
	return n, nil
}

func (c *Config) validate() error {
	missing := []string{}
	checkStr := func(name, val string) {
		if val == "" {
			missing = append(missing, "-"+name)
		}
	}
	checkStr("tenant-id", c.TenantID)
	checkStr("collector-id", c.CollectorID)
	checkStr("server", c.Server)
	checkStr("client-cert", c.ClientCert)
	checkStr("client-key", c.ClientKey)
	checkStr("trust-bundle", c.TrustBundle)
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %v", missing)
	}

	// Fail fast if cert files don't exist — better than a confusing TLS error
	// on first dial.
	for _, p := range []string{c.ClientCert, c.ClientKey, c.TrustBundle} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("file not readable: %s (%w)", p, err)
		}
	}

	if c.TenantID == "" || c.CollectorID == "" {
		return errors.New("tenant-id and collector-id required")
	}

	return nil
}
