package cpuprofiler

import (
	"bufio"
	"debug/elf"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/ispwatch/collector/internal/ebpf/proc"
)

// symbolizer resolve endereço de user-space → nome de função, lendo
// /proc/<pid>/maps pra achar o módulo do IP e a tabela de símbolos do ELF.
// Self-contained (debug/elf + o utilitário proc) — NÃO importa o pkg ebpf (L7).
//
// Convenção de file-offset igual ao elf.go do tracer: o símbolo é indexado pelo
// OFFSET NO ARQUIVO (vaddr - PT_LOAD.Vaddr + PT_LOAD.Off), e o IP vira file-offset
// via a região do maps (ip - regiao.start + regiao.offset). Assim PIE, .so e
// não-PIE caem todos no mesmo espaço sem calcular load-bias.
//
// Limitações conhecidas (v1): binário stripped sem .symtab/.dynsym → cai no nome
// do módulo; Go stripped (símbolos no .gopclntab) idem; JVM (JIT) não tem símbolo
// ELF → o JFR cobre Java. Frames sem frame-pointer saem truncados (limite do
// unwinder do kernel, não da simbolização).
type symbolizer struct {
	modCache  map[string]*modSyms   // chave dev:inode → símbolos (nil = parseado, sem símbolo)
	mapsCache map[uint32][]procMap  // por flush; limpo no resetWindow
}

func newSymbolizer() *symbolizer {
	return &symbolizer{
		modCache:  make(map[string]*modSyms),
		mapsCache: make(map[uint32][]procMap),
	}
}

// resetWindow zera o cache de maps (chamado a cada flush). O cache de módulos
// (caro) persiste entre janelas — símbolos de um arquivo não mudam.
func (s *symbolizer) resetWindow() {
	s.mapsCache = make(map[uint32][]procMap)
	if len(s.modCache) > 4096 { // backstop: não cresce sem limite
		s.modCache = make(map[string]*modSyms)
	}
}

// user devolve o nome da função do IP no processo pid. Sempre devolve algo:
// símbolo, senão o módulo (basename), senão o hex.
func (s *symbolizer) user(pid uint32, ip uint64) string {
	hex := "0x" + strconv.FormatUint(ip, 16)
	maps := s.mapsFor(pid)
	for i := range maps {
		m := &maps[i]
		if ip < m.start || ip >= m.end {
			continue
		}
		fileOff := ip - m.start + m.offset
		if mod := s.modFor(pid, m.path); mod != nil {
			if name := mod.resolve(fileOff); name != "" {
				return name
			}
		}
		return filepath.Base(m.path) // módulo conhecido, símbolo não
	}
	return hex
}

// mapsFor lê e cacheia as regiões executáveis de /proc/<pid>/maps (por flush).
func (s *symbolizer) mapsFor(pid uint32) []procMap {
	if m, ok := s.mapsCache[pid]; ok {
		return m
	}
	maps := parseProcMaps(pid)
	s.mapsCache[pid] = maps
	return maps
}

// modFor parseia (e cacheia por dev:inode) os símbolos do módulo mapPath visto
// pelo processo pid. Retorna nil se não há símbolos.
func (s *symbolizer) modFor(pid uint32, mapPath string) *modSyms {
	full := proc.Path(pid, "root", mapPath)
	key := mapPath
	if st, err := os.Stat(full); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			key = strconv.FormatUint(sys.Dev, 16) + ":" + strconv.FormatUint(sys.Ino, 10)
		}
	}
	if mod, ok := s.modCache[key]; ok {
		return mod
	}
	mod := buildModSyms(full)
	s.modCache[key] = mod // cacheia inclusive nil (negativo)
	return mod
}

// procMap = uma região executável de /proc/<pid>/maps.
type procMap struct {
	start, end, offset uint64
	path               string
}

// parseProcMaps lê as regiões com permissão de execução e caminho de arquivo.
func parseProcMaps(pid uint32) []procMap {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []procMap
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "start-end perms offset dev inode pathname"
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		perms := fields[1]
		if len(perms) < 3 || perms[2] != 'x' { // só regiões executáveis
			continue
		}
		path := fields[5]
		if path == "" || path[0] != '/' { // pula [heap]/[stack]/anon
			continue
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		off, err3 := strconv.ParseUint(fields[2], 16, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, procMap{start: start, end: end, offset: off, path: path})
	}
	return out
}

// modSyms = símbolos STT_FUNC de um módulo, por FILE OFFSET, ordenados.
type modSyms struct {
	offs  []uint64
	sizes []uint64
	names []string
}

// resolve devolve o nome do símbolo cujo [off, off+size) contém fileOff ("" se nenhum).
func (m *modSyms) resolve(fileOff uint64) string {
	i := sort.Search(len(m.offs), func(i int) bool { return m.offs[i] > fileOff }) - 1
	if i < 0 {
		return ""
	}
	if m.sizes[i] > 0 && fileOff >= m.offs[i]+m.sizes[i] {
		return "" // além do fim do símbolo (buraco entre funções)
	}
	return m.names[i]
}

// buildModSyms abre o ELF e indexa as funções por file-offset. Retorna nil se o
// arquivo não abre ou não tem símbolo de função.
func buildModSyms(path string) *modSyms {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// segmentos PT_LOAD executáveis: pra traduzir vaddr do símbolo → file offset.
	type seg struct{ vaddr, memsz, off uint64 }
	var loads []seg
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			loads = append(loads, seg{p.Vaddr, p.Memsz, p.Off})
		}
	}

	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	type entry struct {
		off, size uint64
		name      string
	}
	var entries []entry
	add := func(list []elf.Symbol) {
		for i := range list {
			s := &list[i]
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
				continue
			}
			off := s.Value
			for _, l := range loads {
				if l.vaddr <= s.Value && s.Value < l.vaddr+l.memsz {
					off = s.Value - l.vaddr + l.off
					break
				}
			}
			entries = append(entries, entry{off: off, size: s.Size, name: s.Name})
		}
	}
	add(syms)
	add(dyn)
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].off < entries[j].off })

	m := &modSyms{
		offs:  make([]uint64, len(entries)),
		sizes: make([]uint64, len(entries)),
		names: make([]string, len(entries)),
	}
	for i, e := range entries {
		m.offs[i], m.sizes[i], m.names[i] = e.off, e.size, e.name
	}
	return m
}
