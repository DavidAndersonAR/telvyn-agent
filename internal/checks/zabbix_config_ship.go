// zabbix_config_ship.go — leitura, redact e envio dos arquivos de
// configuração do Zabbix server/agentd que estão no host local.
//
// É chamado pelo check zabbix.sync no primeiro tick e a cada N ticks
// pra detectar mudanças (sha256 sentinel). Em ambientes onde o agent
// não tem leitura ao /etc/zabbix (Zabbix em container separado), os
// caminhos não vão existir e o ship simplesmente faz no-op.
//
// Segurança: as chaves listadas em redactPatterns são substituídas por
// `<REDACTED>` ANTES de qualquer envio. Backend não vê senhas.
package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Caminhos default — apenas os típicos de Linux. Pra Zabbix em Docker
// o operador precisa montar /etc/zabbix do container no host (volume) ou
// usar SHM/copy. Detecção mais sofisticada (k8s configmap, etc) fica pra
// uma futura iteração.
var defaultZabbixConfPaths = []string{
	"/etc/zabbix/zabbix_server.conf",
	"/etc/zabbix/zabbix_agentd.conf",
	"/etc/zabbix/zabbix_proxy.conf",
}

// redactKeyRegex casa "Chave =" ou "Chave=" no começo da linha pra
// substituir o valor por <REDACTED>. Lista conservadora — só remove
// segredos óbvios. Tunables (StartPollers, CacheSize etc) não entram aqui.
var redactKeyRegex = regexp.MustCompile(
	`(?im)^(DBPassword|TLSPSKIdentity|TLSPSKFile|TLSCAFile|TLSCRLFile|TLSCertFile|TLSKeyFile|SourceIP)\s*=.*$`,
)

// redactedFile retorna o conteúdo com segredos redactados + sha256 do
// resultado. Lê de path; erros (não existe / sem permissão) viram (nil, err).
func redactedFile(path string) (filename, content, sha256hex string, err error) {
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return "", "", "", readErr
	}
	redacted := redactKeyRegex.ReplaceAllStringFunc(string(raw), func(line string) string {
		eq := strings.Index(line, "=")
		if eq < 0 {
			return line
		}
		return line[:eq+1] + "<REDACTED>"
	})
	sum := sha256.Sum256([]byte(redacted))
	return path, redacted, hex.EncodeToString(sum[:]), nil
}

// shipConfigFiles tenta ler todos os defaultZabbixConfPaths, redacta o
// que encontrar e posta no endpoint backend. Erro em algum arquivo não
// derruba os outros — só loga e segue.
//
// Retorna (sent, errored). sent é o count de arquivos efetivamente
// enviados; errored conta path that existiam mas falharam.
func (c *zabbixSyncCheck) shipConfigFiles(ctx context.Context) (int, int) {
	type configFile struct {
		Filename string `json:"filename"`
		Content  string `json:"content"`
		Sha256   string `json:"sha256"`
	}
	type payload struct {
		MonitorID string       `json:"monitor_id"`
		Files     []configFile `json:"files"`
	}

	files := make([]configFile, 0, 3)
	errored := 0
	for _, p := range defaultZabbixConfPaths {
		fn, content, sum, err := redactedFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				c.log.Debug("zabbix.sync config read failed", "path", p, "err", err)
				errored++
			}
			continue
		}
		files = append(files, configFile{Filename: fn, Content: content, Sha256: sum})
	}
	if len(files) == 0 {
		return 0, errored
	}

	body, err := PostJSON(ctx, "/api/collector/v1/zabbix/config-files", payload{
		MonitorID: c.monitorID,
		Files:     files,
	})
	if err != nil {
		c.log.Warn("zabbix.sync config ship failed",
			"err", err, "body", truncateString(string(body), 200), "tried", len(files))
		return 0, len(files) + errored
	}
	c.log.Info("zabbix.sync config shipped", "files", len(files))
	return len(files), errored
}

// configPathsForOverride permite testes injetarem paths custom.
// Não usado em produção — apenas suporte a unit tests futuros.
func configPathsForOverride(paths []string) {
	if len(paths) > 0 {
		defaultZabbixConfPaths = paths
	}
}

// fmtBytes não usado por enquanto; mantido pra debug futuro.
var _ = fmt.Sprintf
