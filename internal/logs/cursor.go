// cursor.go — persiste offset+inode de cada container log file pra sobreviver
// restarts do agent sem re-ler tudo. Formato: JSON simples (mapa container_id →
// {offset, inode}). Arquivo default: /var/lib/ispwatch/log_cursors.json.
//
// Best-effort: se não conseguir ler/gravar o arquivo, o tailer reinicia do EOF
// (comportamento degradado mas não fatal).
package logs

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const DefaultCursorPath = "/var/lib/ispwatch/log_cursors.json"

// CursorEntry armazena o estado de progresso de um container log file.
type CursorEntry struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

// CursorStore gerencia persistência de cursors em disco.
type CursorStore struct {
	path string
	log  *slog.Logger

	mu      sync.Mutex
	cursors map[string]CursorEntry // container_id → entry
}

// NewCursorStore carrega cursors existentes do disco. Se o arquivo não existe,
// começa vazio (agent recém-instalado ou primeiro boot com docker logs).
func NewCursorStore(path string, log *slog.Logger) *CursorStore {
	cs := &CursorStore{
		path:    path,
		log:     log.With("component", "docker-logs-cursor"),
		cursors: make(map[string]CursorEntry),
	}
	cs.load()
	return cs
}

// Get retorna o cursor de um container. ok=false se não há cursor salvo.
func (cs *CursorStore) Get(containerID string) (CursorEntry, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.cursors[containerID]
	return e, ok
}

// Set atualiza o cursor de um container em memória.
func (cs *CursorStore) Set(containerID string, entry CursorEntry) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cursors[containerID] = entry
}

// Remove deleta o cursor de um container (ex: container removido).
func (cs *CursorStore) Remove(containerID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.cursors, containerID)
}

// Flush persiste todos os cursors em disco. Chamado periodicamente pelo tailer.
func (cs *CursorStore) Flush() {
	cs.mu.Lock()
	snapshot := make(map[string]CursorEntry, len(cs.cursors))
	for k, v := range cs.cursors {
		snapshot[k] = v
	}
	cs.mu.Unlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		cs.log.Warn("marshal cursors failed", "err", err)
		return
	}

	// Ensure parent dir exists.
	dir := filepath.Dir(cs.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		cs.log.Warn("create cursor dir failed", "path", dir, "err", err)
		return
	}

	// Atomic write via temp file + rename.
	tmp := cs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		cs.log.Warn("write cursor tmp failed", "err", err)
		return
	}
	if err := os.Rename(tmp, cs.path); err != nil {
		cs.log.Warn("rename cursor file failed", "err", err)
		_ = os.Remove(tmp)
	}
}

// load carrega cursors do disco. Falha silenciosa.
func (cs *CursorStore) load() {
	data, err := os.ReadFile(cs.path)
	if err != nil {
		if !os.IsNotExist(err) {
			cs.log.Warn("read cursor file failed", "path", cs.path, "err", err)
		}
		return
	}
	var loaded map[string]CursorEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		cs.log.Warn("unmarshal cursor file failed", "err", err)
		return
	}
	cs.cursors = loaded
	cs.log.Info("loaded log cursors", "count", len(loaded))
}
