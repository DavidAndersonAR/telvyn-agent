package cpuprofiler

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

// kallsyms resolve endereço de kernel → nome de função, lendo /proc/kallsyms uma
// vez e fazendo busca binária (maior símbolo <= endereço). Frames de user NÃO
// passam por aqui (ELF por processo é S3).
type kallsyms struct {
	addrs []uint64
	names []string
}

// loadKallsyms lê /proc/kallsyms. Devolve nil se indisponível ou se kptr_restrict
// zera os endereços (sem CAP_SYSLOG) — aí os frames de kernel saem em hex.
func loadKallsyms() *kallsyms {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil
	}
	defer f.Close()

	k := &kallsyms{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// formato: "<addr> <type> <name> [module]"
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		k.addrs = append(k.addrs, addr)
		k.names = append(k.names, fields[2])
	}
	if len(k.addrs) == 0 {
		return nil // kptr_restrict provavelmente
	}
	// kallsyms já vem ordenado por endereço, mas garantimos pra busca binária.
	if !sort.IsSorted(k) {
		sort.Sort(k)
	}
	return k
}

func (k *kallsyms) Len() int           { return len(k.addrs) }
func (k *kallsyms) Less(i, j int) bool { return k.addrs[i] < k.addrs[j] }
func (k *kallsyms) Swap(i, j int) {
	k.addrs[i], k.addrs[j] = k.addrs[j], k.addrs[i]
	k.names[i], k.names[j] = k.names[j], k.names[i]
}

// resolve devolve o nome do maior símbolo com endereço <= addr ("" se nenhum).
func (k *kallsyms) resolve(addr uint64) string {
	i := sort.Search(len(k.addrs), func(i int) bool { return k.addrs[i] > addr }) - 1
	if i < 0 {
		return ""
	}
	return k.names[i]
}
