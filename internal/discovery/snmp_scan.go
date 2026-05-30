// Package discovery — Phase 3 Plan 05.
//
// ScanSNMP varre um ou mais CIDRs probando UDP/161 com community/v3
// configurada. Para cada IP que responde sysObjectID (1.3.6.1.2.1.1.2.0)
// monta um Candidate com profile suggestion via snmp.MatchSysObjectID.
//
// Rate limit OBRIGATORIO (Pitfall 5 do RESEARCH): scan de /16 sem
// semaphore + sleep gera storm UDP visto como reconnaissance attack
// por IDS do cliente. Defaults: 50 concurrent, sleep 50ms entre batches,
// per-host timeout 1s.
//
// Esta operacao envia SNMP GET pra cada IP do CIDR — IDS/SIEM podem
// flaggar como port scan. Use somente em redes que voce possui ou tem
// autorizacao explicita pra auditar. CIDR e input explicito do operador,
// nunca derivado da subnet local do agent.
package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/ispwatch/collector/internal/snmp"
)

// ScanParams espelha snmp.Params + knobs de rate limit. Exposto neste
// pacote pra que o caller (check snmp.autodiscover) nao importe gosnmp
// diretamente.
type ScanParams struct {
	// SNMP creds + version.
	Version       string
	Community     string
	V3User        string
	V3AuthProto   string
	V3AuthPass    string
	V3PrivProto   string
	V3PrivPass    string
	V3ContextName string

	// PerHostTimeout — deadline UDP por IP. Default 1s.
	PerHostTimeout time.Duration
	// Concurrency — max goroutines simultaneas (semaphore). Default 50.
	Concurrency int
	// BatchSleep — pausa entre lotes de Concurrency probes. Default 50ms.
	BatchSleep time.Duration
}

// Candidate descreve um device que respondeu sysObjectID.
type Candidate struct {
	IP                string
	SysObjectID       string
	ProfileSuggestion string // nome do profile via MatchSysObjectID; vazio se sem match
	Port              int
	DiscoveredAt      time.Time
}

// snmpProbe abstrai o subset de operacoes que o scan faz contra um
// device — permite mock em testes sem socket UDP.
type snmpProbe interface {
	GetSysObjectID(ctx context.Context) (string, error)
	Close() error
}

// clientFactory cria um probe pra cada IP. Em prod aponta para o builder
// real (snmp.NewClient + GET sysObjectID); testes substituem.
var clientFactory = newRealProbe

// realProbe envolve snmp.Client expondo apenas GetSysObjectID — o resto
// da API SNMP nao e necessario pra autodiscovery v0.
type realProbe struct{ c *snmp.Client }

func newRealProbe(p snmp.Params) (snmpProbe, error) {
	c, err := snmp.NewClient(p)
	if err != nil {
		return nil, err
	}
	return &realProbe{c: c}, nil
}

func (r *realProbe) GetSysObjectID(ctx context.Context) (string, error) {
	pdus, err := r.c.Get(ctx, []string{"1.3.6.1.2.1.1.2.0"})
	if err != nil {
		return "", err
	}
	if len(pdus) == 0 {
		return "", fmt.Errorf("snmp: sysObjectID nao retornado")
	}
	return fmt.Sprintf("%v", pdus[0].Value), nil
}

func (r *realProbe) Close() error {
	if r.c == nil {
		return nil
	}
	return r.c.Close()
}

// ScanSNMP percorre todos os IPs unicos dos CIDRs informados e devolve
// um Candidate por IP que respondeu sysObjectID. Erros pontuais (timeout,
// no response) sao skip silencioso — so retorna error se CIDR invalido.
func ScanSNMP(ctx context.Context, cidrs []string, p ScanParams) ([]Candidate, error) {
	// Aplicar defaults.
	if p.Concurrency <= 0 {
		p.Concurrency = 50
	}
	if p.PerHostTimeout <= 0 {
		p.PerHostTimeout = 1 * time.Second
	}
	if p.BatchSleep < 0 {
		p.BatchSleep = 0
	}

	// Aglomerar + deduplicar IPs dos CIDRs.
	seen := make(map[string]bool)
	var hosts []string
	for _, cidr := range cidrs {
		hs, err := hostsInCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("discovery: cidr %q: %w", cidr, err)
		}
		for _, h := range hs {
			if seen[h] {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	if len(hosts) == 0 {
		return nil, nil
	}

	sem := semaphore.NewWeighted(int64(p.Concurrency))
	var mu sync.Mutex
	out := make([]Candidate, 0, len(hosts)/4)

	// Carrega perfis uma vez — match por sysObjectID e prefix lookup local.
	profiles, _ := snmp.AllProfiles() // se erro, fica nil → sem match (degradado)

	var wg sync.WaitGroup
	for i, ip := range hosts {
		// Honra cancelamento antes mesmo de acquirir semaphore.
		if ctx.Err() != nil {
			break
		}

		// Rate limit por batch: a cada Concurrency hosts pausa BatchSleep
		// antes de iniciar o proximo batch. Isso suaviza a curva UDP que
		// um IDS veria como reconnaissance.
		if i > 0 && p.BatchSleep > 0 && i%p.Concurrency == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(p.BatchSleep):
			}
		}

		if err := sem.Acquire(ctx, 1); err != nil {
			// ctx cancelado durante Acquire — sai do loop.
			break
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer sem.Release(1)
			c, ok := scanOne(ctx, ip, p, profiles)
			if !ok {
				return
			}
			mu.Lock()
			out = append(out, c)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return out, nil
}

// scanOne faz um GET sysObjectID em ip:161 com a credencial p. Retorna
// (Candidate, true) se respondeu; (zero, false) em qualquer falha.
func scanOne(ctx context.Context, ip string, p ScanParams, profiles []*snmp.Profile) (Candidate, bool) {
	// Sub-deadline curto pra este probe — mesmo que ctx do scan tenha
	// um deadline maior, queremos cortar o probe rapido pra liberar slot
	// do semaphore.
	probeCtx, cancel := context.WithTimeout(ctx, p.PerHostTimeout)
	defer cancel()

	params := snmp.Params{
		Target:        ip + ":161",
		Version:       firstNonEmpty(p.Version, "v2c"),
		Timeout:       p.PerHostTimeout,
		Community:     p.Community,
		V3User:        p.V3User,
		V3AuthProto:   p.V3AuthProto,
		V3AuthPass:    p.V3AuthPass,
		V3PrivProto:   p.V3PrivProto,
		V3PrivPass:    p.V3PrivPass,
		V3ContextName: p.V3ContextName,
	}

	probe, err := clientFactory(params)
	if err != nil {
		return Candidate{}, false
	}
	defer probe.Close()

	sysOid, err := probe.GetSysObjectID(probeCtx)
	if err != nil {
		return Candidate{}, false
	}
	sysOid = strings.TrimSpace(sysOid)
	if sysOid == "" {
		return Candidate{}, false
	}

	c := Candidate{
		IP:           ip,
		SysObjectID:  sysOid,
		Port:         161,
		DiscoveredAt: time.Now().UTC(),
	}
	if profiles != nil {
		if match, ok := snmp.MatchSysObjectID(profiles, sysOid); ok && match != nil {
			c.ProfileSuggestion = match.Name
		}
	}
	return c, true
}

// hostsInCIDR expande um CIDR em IPs. Convencao:
//   - /31 e /32 sao mantidos integralmente (PtP / loopback);
//   - /30 e maiores: descarta network address + broadcast.
//
// IPv6 nao e suportado nesta plan — Pitfall 5 dimensiona pra IPv4 ranges
// tipicos de management ISP.
func hostsInCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, err
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("ipv6 not supported: %s", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	// Tamanho total = 2^(bits-ones). Pra /32 e /31 retornar todos.
	size := 1 << (bits - ones)
	out := make([]string, 0, size)

	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	for i := 0; i < size; i++ {
		out = append(out, ip.String())
		ipInc(ip)
	}

	// Trim network + broadcast pra /30 e maiores (size > 2).
	if size > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// ipInc incrementa o IP in-place (big-endian, sem overflow check —
// callers usam dentro de loop limitado por size).
func ipInc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}
