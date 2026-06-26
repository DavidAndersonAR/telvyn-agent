package cpuprofiler

import (
	"bufio"
	"debug/elf"
	"debug/gosym"
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
// Go stripped (-s -w) NÃO tem .symtab/.dynsym, mas Go SEMPRE carrega o .gopclntab
// (usado pelo runtime p/ stack trace) — então caímos no debug/gosym e simbolizamos
// igual. Limitações que sobram: binário C/Rust stripped → nome do módulo; JVM (JIT)
// não tem símbolo ELF → o JFR cobre Java; frames sem frame-pointer saem truncados
// (limite do unwinder do kernel, não da simbolização).
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

// elfLoad = um segmento PT_LOAD executável (pra traduzir vaddr → file-offset).
type elfLoad struct{ off, vaddr, memsz uint64 }

// symEntry = uma função {file-offset, tamanho, nome}.
type symEntry struct {
	off, size uint64
	name      string
}

// modSyms = funções de um módulo, por FILE OFFSET, ordenadas (busca binária).
// LEVE por design (só nome+endereço) — vem do .symtab/.dynsym OU, em binário Go
// stripped, do .gopclntab (extraído e DESCARTADO; o cache guarda só este índice).
type modSyms struct {
	offs  []uint64
	sizes []uint64
	names []string
}

// resolve devolve o nome da função que contém fileOff ("" se nenhuma).
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
// arquivo não abre ou não tem nem símbolo ELF nem .gopclntab utilizável.
func buildModSyms(path string) *modSyms {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// segmentos PT_LOAD executáveis: pra traduzir vaddr → file offset.
	var loads []elfLoad
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			loads = append(loads, elfLoad{off: p.Off, vaddr: p.Vaddr, memsz: p.Memsz})
		}
	}
	vaddrToOff := func(v uint64) uint64 {
		for _, l := range loads {
			if l.vaddr <= v && v < l.vaddr+l.memsz {
				return v - l.vaddr + l.off
			}
		}
		return v
	}

	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	var entries []symEntry
	add := func(list []elf.Symbol) {
		for i := range list {
			s := &list[i]
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
				continue
			}
			entries = append(entries, symEntry{off: vaddrToOff(s.Value), size: s.Size, name: s.Name})
		}
	}
	add(syms)
	add(dyn)
	if len(entries) == 0 {
		// Sem .symtab/.dynsym (stripped). Se for Go, os nomes estão no .gopclntab.
		entries = goSymEntries(f, vaddrToOff)
		if len(entries) == 0 {
			return nil
		}
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

// maxPclnSize: teto do .gopclntab pra extrair via gosym. Só serviços-pod chegam
// aqui (o flush pula host/kernel antes de simbolizar), então é generoso o
// suficiente pra cobrir até um traefik. A Table é construída e DESCARTADA (só o
// índice leve fica), então o custo é transitório; o teto é só uma rede de
// segurança contra um binário patológico. Acima dele: cai no nome do módulo.
const maxPclnSize = 32 << 20 // 32 MiB

// goSymEntries extrai {off,size,name} do .gopclntab de um binário Go (presente
// até em stripped). Constrói a gosym.Table SÓ pra ler a lista de funções e a
// DESCARTA — o que sobra/cacheia é o índice leve, não a Table. Recover porque o
// debug/gosym pode dar panic em pcln malformado (um panic na goroutine do
// profiler derrubaria o agente inteiro).
func goSymEntries(f *elf.File, vaddrToOff func(uint64) uint64) (entries []symEntry) {
	defer func() {
		if recover() != nil {
			entries = nil
		}
	}()
	sec := f.Section(".gopclntab")
	if sec == nil || sec.Size == 0 || sec.Size > maxPclnSize {
		return nil
	}
	data, err := sec.Data()
	if err != nil || len(data) == 0 {
		return nil
	}
	var textAddr uint64
	if t := f.Section(".text"); t != nil {
		textAddr = t.Addr
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, textAddr))
	if err != nil || tab == nil {
		return nil
	}
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		if fn.Sym == nil || fn.Entry == 0 || fn.Name == "" {
			continue
		}
		var size uint64
		if fn.End > fn.Entry {
			size = fn.End - fn.Entry
		}
		entries = append(entries, symEntry{off: vaddrToOff(fn.Entry), size: size, name: fn.Name})
	}
	return entries
}
