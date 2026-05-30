// json_reader.go — per-container log file reader. Tails the Docker json-file
// log at /var/lib/docker/containers/<id>/<id>-json.log, parsing each line as:
//
//   {"log":"...message...\n","stream":"stdout","time":"2024-01-02T03:04:05.678Z"}
//
// Handles rotation: detects file truncation (offset > current size) or inode
// change and reopens from the beginning. Polling-based (no fsnotify dep).
package logs

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// pollInterval — como não usamos fsnotify, fazemos poll a cada 100ms.
	pollInterval = 100 * time.Millisecond

	// maxLineLen — linhas maiores que 256KB são truncadas. Docker json-file
	// driver já limita ~16KB por default, mas logs raw podem ser maiores.
	maxLineLen = 256 * 1024
)

// dockerLogLine é o shape JSON de cada linha do json-file driver.
type dockerLogLine struct {
	Log    string `json:"log"`
	Stream string `json:"stream"`
	Time   string `json:"time"`
}

// ContainerMeta contém info do container pra enriquecer cada log record.
type ContainerMeta struct {
	ContainerID   string
	ContainerName string
	ServiceName   string
	ImageName     string
}

// LogEntry é o record parseado pronto pra enviar ao exporter.
type LogEntry struct {
	TimestampUnixNano int64
	Body              string
	Stream            string // "stdout" | "stderr"
	Meta              ContainerMeta
}

// JSONFileReader tails um único arquivo de log de container Docker.
type JSONFileReader struct {
	logPath string
	meta    ContainerMeta
	log     *slog.Logger
	out     chan<- LogEntry

	// Rate limiting: bytes/s por container.
	rateLimitBytesPerSec int64
	bytesThisWindow      int64
	windowStart          time.Time
	droppedLines         atomic.Int64

	// Cursor state.
	cursorStore *CursorStore
	offset      int64
	inode       uint64
	file        *os.File
	scanner     *bufio.Scanner
}

// NewJSONFileReader cria um reader pra um container log file.
func NewJSONFileReader(
	logPath string,
	meta ContainerMeta,
	cursorStore *CursorStore,
	rateLimitBytesPerSec int64,
	out chan<- LogEntry,
	log *slog.Logger,
) *JSONFileReader {
	r := &JSONFileReader{
		logPath:              logPath,
		meta:                 meta,
		log:                  log.With("component", "json-reader", "container", meta.ContainerName),
		out:                  out,
		rateLimitBytesPerSec: rateLimitBytesPerSec,
		cursorStore:          cursorStore,
		windowStart:          time.Now(),
	}
	// Restore cursor if available. When no cursor exists (first time seeing
	// this container) start from end of file — avoids flooding the exporter
	// with potentially GB of backlog on first deploy.
	if entry, ok := cursorStore.Get(meta.ContainerID); ok {
		r.offset = entry.Offset
		r.inode = entry.Inode
	} else {
		if stat, err := os.Stat(logPath); err == nil {
			r.offset = stat.Size()
			if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
				r.inode = sys.Ino
			}
			r.log.Info("no prior cursor, starting from end of file", "offset", r.offset)
		}
	}
	return r
}

// Run polls the log file until ctx is done. Blocking call.
func (r *JSONFileReader) Run(done <-chan struct{}) {
	defer r.closeFile()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			r.saveCursor()
			return
		case <-ticker.C:
			r.readAvailable()
		}
	}
}

// DroppedLines retorna o total de linhas dropadas por rate limit.
func (r *JSONFileReader) DroppedLines() int64 {
	return r.droppedLines.Load()
}

// readAvailable lê todas as linhas disponíveis no arquivo.
func (r *JSONFileReader) readAvailable() {
	if err := r.ensureOpen(); err != nil {
		return
	}

	for r.scanner.Scan() {
		line := r.scanner.Bytes()
		lineLen := int64(len(line)) + 1 // +1 for newline

		// Rate limit check.
		if r.rateLimitBytesPerSec > 0 {
			now := time.Now()
			if now.Sub(r.windowStart) >= time.Second {
				r.bytesThisWindow = 0
				r.windowStart = now
			}
			if r.bytesThisWindow+lineLen > r.rateLimitBytesPerSec {
				r.droppedLines.Add(1)
				r.offset += lineLen
				continue
			}
			r.bytesThisWindow += lineLen
		}

		r.offset += lineLen

		entry, ok := r.parseLine(line)
		if !ok {
			continue
		}

		select {
		case r.out <- entry:
		default:
			// Channel full — drop silently.
			r.droppedLines.Add(1)
		}
	}

	// Scanner error (EOF is nil, so we only get real errors here).
	if err := r.scanner.Err(); err != nil {
		r.log.Debug("scanner error, will reopen", "err", err)
		r.closeFile()
	}
}

// ensureOpen abre (ou reabre) o arquivo se necessário. Detecta truncation
// e inode changes (log rotation).
func (r *JSONFileReader) ensureOpen() error {
	stat, err := os.Stat(r.logPath)
	if err != nil {
		if !os.IsNotExist(err) {
			r.log.Debug("stat log file failed", "err", err)
		}
		r.closeFile()
		return err
	}

	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		r.closeFile()
		return os.ErrInvalid
	}

	currentInode := sysStat.Ino
	currentSize := stat.Size()

	// Detect truncation (logrotate copytruncate) or inode change (rotation).
	needReopen := false
	if r.file == nil {
		needReopen = true
	} else if currentInode != r.inode {
		// Inode changed — file was rotated.
		r.log.Info("inode changed, reopening from start", "old", r.inode, "new", currentInode)
		r.offset = 0
		needReopen = true
	} else if currentSize < r.offset {
		// File truncated.
		r.log.Info("file truncated, reopening from start", "size", currentSize, "offset", r.offset)
		r.offset = 0
		needReopen = true
	}

	if !needReopen {
		return nil
	}

	r.closeFile()

	f, err := os.Open(r.logPath)
	if err != nil {
		r.log.Debug("open log file failed", "err", err)
		return err
	}

	// Seek to saved offset.
	if r.offset > 0 {
		newOff, err := f.Seek(r.offset, io.SeekStart)
		if err != nil {
			// Seek failed — start from beginning.
			r.log.Warn("seek failed, reading from start", "err", err)
			r.offset = 0
		} else {
			r.offset = newOff
		}
	}

	r.file = f
	r.inode = currentInode
	r.scanner = bufio.NewScanner(f)
	r.scanner.Buffer(make([]byte, 0, maxLineLen), maxLineLen)

	return nil
}

// parseLine decodifica uma linha JSON do docker json-file format.
func (r *JSONFileReader) parseLine(line []byte) (LogEntry, bool) {
	var dl dockerLogLine
	if err := json.Unmarshal(line, &dl); err != nil {
		return LogEntry{}, false
	}
	if dl.Log == "" {
		return LogEntry{}, false
	}

	// Parse timestamp.
	t, err := time.Parse(time.RFC3339Nano, dl.Time)
	if err != nil {
		t = time.Now()
	}

	// Trim trailing newline from log message (Docker always appends \n).
	body := strings.TrimSuffix(dl.Log, "\n")

	return LogEntry{
		TimestampUnixNano: t.UnixNano(),
		Body:              body,
		Stream:            dl.Stream,
		Meta:              r.meta,
	}, true
}

// saveCursor persiste o offset atual no CursorStore.
func (r *JSONFileReader) saveCursor() {
	r.cursorStore.Set(r.meta.ContainerID, CursorEntry{
		Offset: r.offset,
		Inode:  r.inode,
	})
}

// closeFile fecha o file handle se aberto.
func (r *JSONFileReader) closeFile() {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
		r.scanner = nil
	}
}
