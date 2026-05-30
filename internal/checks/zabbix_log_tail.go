// zabbix_log_tail.go — Tail incremental do zabbix_server.log com offset
// persistido em /var/lib/ispwatch-collector/zabbix_log_cursor.json. A cada
// tick do zabbix.sync, lê o que cresceu desde a última posição, parseia
// linha por linha e posta um batch para o backend mTLS.
//
// Detecção de rotação:
//   - Se o tamanho do arquivo diminuir (truncated) ou o inode mudar
//     (logrotate criando arquivo novo), reseta offset pra 0.
//   - Não tenta ler o arquivo .1 antigo — perdas de N segundos em rotação
//     são aceitáveis. Reload é raro.
//
// Formato Zabbix:
//   <pid>:<YYYYMMDD>:<HHMMSS.mmm> [<process_type> #N] <message>
// Exemplos:
//   12345:20260520:214701.234 server #0 started [main process]
//   12346:20260520:214702.111 cannot connect to MySQL: Access denied
//
// Severidade não é nativa; inferida por keywords (ERROR/Failed/cannot →
// error; warning/slow → warning; debug → debug; resto → info).
package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultZabbixLogPath = "/var/log/zabbix/zabbix_server.log"
	logTailMaxBatch      = 500
	logTailMaxLineBytes  = 8000
)

func defaultLogCursorPath() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/ispwatch-collector/zabbix_log_cursor.json"
	}
	return "./zabbix_log_cursor.json"
}

// logCursor — estado persistido entre execuções do agent.
type logCursor struct {
	Filename   string `json:"filename"`
	Offset     int64  `json:"offset"`
	Inode      uint64 `json:"inode"`
	UpdatedAt  string `json:"updated_at"`
}

func loadLogCursor(path string) logCursor {
	var c logCursor
	raw, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	_ = json.Unmarshal(raw, &c)
	return c
}

func saveLogCursor(path string, c logCursor) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	buf, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// statInode retorna o inode (linux) ou 0 em outras plataformas. Usado pra
// detectar logrotate "create" mode (mesmo path, inode novo).
func statInode(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}

// zabbixLogLineRE casa o cabeçalho: pid:date:time
var zabbixLogLineRE = regexp.MustCompile(`^(\d+):(\d{8}):(\d{6}\.\d{3})\s+(.*)$`)

// processTypeRE extrai "[main process]" / "[poller #3]" / "[trapper #5]" etc.
var processTypeRE = regexp.MustCompile(`\[([a-zA-Z_ ]+?)(?:\s+#\d+)?\]`)

// logEvent espelha o DTO do backend.
type logEvent struct {
	TS          string  `json:"ts"`
	PID         *int    `json:"pid,omitempty"`
	Severity    string  `json:"severity"`
	ProcessType *string `json:"process_type,omitempty"`
	Message     string  `json:"message"`
}

// parseZabbixLogLine devolve nil quando a linha não casa o cabeçalho
// (continuation de linha anterior, ou linha vazia).
func parseZabbixLogLine(line string) *logEvent {
	if len(line) == 0 || len(line) > logTailMaxLineBytes {
		return nil
	}
	// Zabbix alinha PIDs em 5/6 colunas com leading spaces ("   235:..."),
	// principalmente em linhas que seguem uma continuation. TrimLeft remove
	// só whitespace inicial — preserva o resto.
	line = strings.TrimLeft(line, " \t")
	m := zabbixLogLineRE.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	pid64, _ := strconv.Atoi(m[1])
	date := m[2] // YYYYMMDD
	tt := m[3]   // HHMMSS.mmm
	rest := m[4]

	// Reformata pra ISO 8601 UTC. O log do Zabbix grava em horário local do
	// servidor; aqui assumimos UTC (cliente pode pisar o TZ via env).
	if len(date) != 8 || len(tt) != 10 {
		return nil
	}
	iso := fmt.Sprintf("%s-%s-%sT%s:%s:%s.%sZ",
		date[0:4], date[4:6], date[6:8],
		tt[0:2], tt[2:4], tt[4:6], tt[7:10])

	var procPtr *string
	if pm := processTypeRE.FindStringSubmatch(rest); pm != nil {
		p := strings.TrimSpace(pm[1])
		procPtr = &p
		// Não strip do message — a presença do `[process]` é útil pra
		// quem lê o log puro.
	}

	pid := pid64
	return &logEvent{
		TS:          iso,
		PID:         &pid,
		Severity:    inferSeverity(rest),
		ProcessType: procPtr,
		Message:     rest,
	}
}

// inferSeverity heurística baseada em substring case-insensitive. Conservadora:
// preferimos rotular como "info" quando ambíguo.
func inferSeverity(msg string) string {
	l := strings.ToLower(msg)
	if strings.Contains(l, "cannot ") ||
		strings.Contains(l, "failed") ||
		strings.Contains(l, "fatal") ||
		strings.Contains(l, "error") ||
		strings.Contains(l, "denied") ||
		strings.Contains(l, "unreachable") {
		return "error"
	}
	if strings.Contains(l, "warning") ||
		strings.Contains(l, "slow ") ||
		strings.Contains(l, "deprecated") ||
		strings.Contains(l, "skipped") {
		return "warning"
	}
	if strings.Contains(l, "debug") {
		return "debug"
	}
	return "info"
}

// shipLogTail é a função pública chamada pelo zabbix.sync a cada tick.
// Faz no-op silencioso se o arquivo não existir (Zabbix em container
// separado sem volume montado, ou path diferente do default).
func (c *zabbixSyncCheck) shipLogTail(ctx context.Context) (int, error) {
	path := c.logFilePath
	if path == "" {
		path = defaultZabbixLogPath
	}
	cursorPath := defaultLogCursorPath()
	filename := filepath.Base(path)

	fi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			c.log.Debug("zabbix.sync log tail stat failed", "path", path, "err", err)
		}
		return 0, nil
	}

	cur := loadLogCursor(cursorPath)
	inode := statInode(fi)
	size := fi.Size()

	// Detecta rotação: arquivo encolheu OU inode mudou OU primeira execução
	// num arquivo desconhecido.
	if cur.Filename != filename || cur.Offset > size ||
		(cur.Inode != 0 && inode != 0 && cur.Inode != inode) {
		c.log.Info("zabbix.sync log rotation detected, resetting offset",
			"old_offset", cur.Offset, "new_size", size,
			"old_inode", cur.Inode, "new_inode", inode)
		cur = logCursor{Filename: filename}
	}
	if cur.Offset == size {
		return 0, nil // sem novidade
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open log: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(cur.Offset, 0); err != nil {
		return 0, fmt.Errorf("seek: %w", err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), logTailMaxLineBytes)
	events := make([]logEvent, 0, 256)
	bytesRead := int64(0)
	sent := 0

	flush := func() error {
		newOffset := cur.Offset + bytesRead
		// Mesmo sem events parseados precisamos avançar o cursor — caso
		// contrário ficamos reprocessando as mesmas N linhas malformadas
		// a cada tick (gera o falso "log rotation detected").
		if len(events) > 0 {
			type cursorDto struct {
				Offset int64  `json:"offset"`
				Inode  uint64 `json:"inode"`
			}
			type payload struct {
				MonitorID string     `json:"monitor_id"`
				Filename  string     `json:"filename"`
				Cursor    cursorDto  `json:"cursor"`
				Events    []logEvent `json:"events"`
			}
			_, err := PostJSON(ctx, "/api/collector/v1/zabbix/logs", payload{
				MonitorID: c.monitorID,
				Filename:  filename,
				Cursor:    cursorDto{Offset: newOffset, Inode: inode},
				Events:    events,
			})
			if err != nil {
				return err
			}
			sent += len(events)
			events = events[:0]
		}
		// Sempre persiste cursor local pra evitar reprocesso.
		cur.Offset = newOffset
		cur.Inode = inode
		if err := saveLogCursor(cursorPath, cur); err != nil {
			c.log.Warn("zabbix.sync save cursor failed", "err", err)
		}
		return nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		// +1 pelo \n consumido por Scan; aproximação suficiente — em arquivos
		// CRLF terá drift de 1 byte/linha que o reset de rotação corrige.
		bytesRead += int64(len(line)) + 1
		ev := parseZabbixLogLine(line)
		if ev == nil {
			continue
		}
		events = append(events, *ev)
		if len(events) >= logTailMaxBatch {
			if err := flush(); err != nil {
				return sent, err
			}
			// Reinicia bytesRead pra próxima janela. Como flush atualiza
			// cur.Offset, o cálculo de newOffset reaproveita o running total.
			bytesRead = 0
		}
	}
	if err := scanner.Err(); err != nil {
		// Linha grande demais ou IO error — flush o que coletamos e segue.
		c.log.Warn("zabbix.sync scanner err", "err", err)
	}
	if err := flush(); err != nil {
		return sent, err
	}
	return sent, nil
}
