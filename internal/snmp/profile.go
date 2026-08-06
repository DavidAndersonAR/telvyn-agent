// Profile loader — Phase 3 Plan 02.
//
// Carrega perfis SNMP YAML bundled (via internal/snmp/profiles/embed.FS)
// e expoe API consumida pelo check snmp.generic: LoadProfile(name),
// AllProfiles(), MatchSysObjectID(profiles, sysOid).
//
// Shape YAML declarativo (RESEARCH.md Pattern 1):
//
//	sysobjectid:
//	  - <prefix>
//	metrics:
//	  - mib: <name>
//	    symbol: { oid, name }           # scalar
//	  - mib: <name>
//	    table:   { oid, name }          # tabela
//	    symbols: [{ oid, name }, ...]   # colunas
//	    metric_tags:
//	      - { tag, symbol: { oid, name } }   # tag dinamica = valor da coluna ifDescr
//	metric_tags:
//	  - { tag, value }                  # tag estatica do perfil
//
// MatchSysObjectID: prefix match com regra do mais especifico vence.
// Cisco IOS expoe 1.3.6.1.4.1.9.1 (curto) e NX-OS expoe 1.3.6.1.4.1.9.12.3.1.3
// (mais longo) — um sysObjectID Nexus casa os dois, mas o mais longo ganha.
//
// Collect emite metricas escalares e de tabela respeitando o nome simbolico
// definido no YAML; tags sao a uniao de staticTags + profile.MetricTags
// (valor-fixo) + metric_tags da tabela (resolvendo Symbol.OID na mesma row).
// Erros parciais (uma coluna ausente) nao bloqueiam — so falha se TODOS os
// OIDs falharem.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/ispwatch/collector/internal/snmp/profiles"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Profile representa um YAML de perfil SNMP parseado. Name vem do nome
// do arquivo (sem .yaml) — o YAML em si nao carrega "name" pra evitar
// duplicacao com filename.
type Profile struct {
	Name        string             `yaml:"-"`
	SysObjectID []string           `yaml:"sysobjectid"`
	AutoDetect  *bool              `yaml:"auto_detect"`
	Metrics     []ProfileMetric    `yaml:"metrics"`
	MetricTags  []ProfileMetricTag `yaml:"metric_tags"`

	// Novo formato: discovery_rules + items por row.
	// Cada rule executa N walks de keys (= labels) + N walks de items (=
	// medições), e emite metric por (row_index × item) com labels herdados
	// das keys + static_tags. Co-existe com Metrics; ambos rodam em Collect.
	DiscoveryRules []ProfileDiscoveryRule `yaml:"discovery_rules,omitempty"`

	// Metadata é o bloco "metadata:" do perfil NDM — identidade do
	// device (vendor/model/serial/version...) emitida pro noc_device.
	Metadata *ProfileMetadata `yaml:"metadata,omitempty"`
}

// ProfileMetadata é o bloco "metadata:" do profile NDM.
type ProfileMetadata struct {
	Device map[string]ProfileMetaField `yaml:"device"`
}

// ProfileMetaField: um campo de identidade do device — valor estático OU de um OID.
type ProfileMetaField struct {
	Value  string         `yaml:"value,omitempty"`
	Symbol *ProfileSymbol `yaml:"symbol,omitempty"`
}

// ProfileDiscoveryRule é um "discovery rule + item prototypes":
// walks distintos pra labels (keys) e métricas (items), join por
// row_index.
type ProfileDiscoveryRule struct {
	Name       string            `yaml:"name"`
	Keys       []DiscoveryKey    `yaml:"keys"`
	Items      []DiscoveryItem   `yaml:"items"`
	StaticTags map[string]string `yaml:"static_tags,omitempty"`
}

// DiscoveryKey é uma coluna walked uma vez por rule; seu valor (string) vira
// label `Label` em todas as métricas daquela row.
type DiscoveryKey struct {
	Label string `yaml:"label"`
	OID   string `yaml:"oid"`
}

// DiscoveryItem é uma coluna walked uma vez por rule; cada row emite uma
// métrica com __name__=`Name` e value=PduFloat.
type DiscoveryItem struct {
	Name  string  `yaml:"name"`
	OID   string  `yaml:"oid"`
	Scale float64 `yaml:"scale,omitempty"` // multiplicador (ex.: 0.01 centi-dBm→dBm); 0 = sem escala
}

// ProfileMetric e uma entrada do array `metrics:` — pode ser uma metrica
// escalar (Symbol preenchido) ou de tabela (Table + Symbols preenchidos).
// Os dois modos sao mutuamente exclusivos por convencao.
type ProfileMetric struct {
	MIB        string              `yaml:"mib"`
	Symbol     *ProfileSymbol      `yaml:"symbol,omitempty"`
	Table      *ProfileTable       `yaml:"table,omitempty"`
	Symbols    []ProfileSymbol     `yaml:"symbols,omitempty"`
	MetricTags []ProfileMetricTag  `yaml:"metric_tags,omitempty"`
	Filter     *ProfileTableFilter `yaml:"filter,omitempty"`
}

// ProfileTableFilter restringe quais rows de uma tabela viram métricas, casando
// o valor de uma tag (default interface_name) contra regexes. Use pra não
// coletar interfaces irrelevantes — ex.: num OLT, manter só uplinks e portas
// PON, descartando as centenas de portas LAN de ONU de assinante.
//
//   - Include vazio  → toda row passa no passo de inclusão.
//   - Include cheio  → a row só passa se casar ALGUM padrão de include.
//   - Exclude        → tem prioridade: casou, a row cai (mesmo se incluída).
type ProfileTableFilter struct {
	Tag     string   `yaml:"tag,omitempty"`
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`

	compileOnce sync.Once
	incRe       []*regexp.Regexp
	excRe       []*regexp.Regexp
}

// keep decide se a row (pelas tags já resolvidas) deve virar métrica. Regexes
// compilam uma vez (perfil é carregado e cacheado uma vez no processo).
func (f *ProfileTableFilter) keep(tags map[string]string) bool {
	f.compileOnce.Do(func() {
		for _, s := range f.Include {
			if re, err := regexp.Compile(s); err == nil {
				f.incRe = append(f.incRe, re)
			}
		}
		for _, s := range f.Exclude {
			if re, err := regexp.Compile(s); err == nil {
				f.excRe = append(f.excRe, re)
			}
		}
	})
	tagName := f.Tag
	if tagName == "" {
		tagName = "interface_name"
	}
	v := tags[tagName]
	if len(f.incRe) > 0 {
		matched := false
		for _, re := range f.incRe {
			if re.MatchString(v) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, re := range f.excRe {
		if re.MatchString(v) {
			return false
		}
	}
	return true
}

// ProfileSymbol descreve um OID com nome simbolico — o nome canonico que
// vira o MetricName na saida do Collect.
type ProfileSymbol struct {
	OID   string  `yaml:"oid"`
	Name  string  `yaml:"name"`
	Scale float64 `yaml:"scale,omitempty"` // multiplicador aplicado ao valor (0 = sem escala)
}

// ProfileTable identifica a raiz de uma tabela SMI. O OID e a raiz da
// entry (e.g. 1.3.6.1.2.1.2.2 para ifTable) — WalkTable expande para
// <root>.1.<col>.<rowIndex>.
type ProfileTable struct {
	OID  string `yaml:"oid"`
	Name string `yaml:"name"`
}

// ProfileMetricTag e uma tag aplicada a metricas. Duas formas:
//   - Estatica: { tag: vendor, value: linux-net-snmp }
//   - Dinamica: { tag: interface_name, symbol: { oid: ..., name: ifDescr } }
//     resolve buscando o valor da coluna na mesma row da tabela.
type ProfileMetricTag struct {
	Tag    string         `yaml:"tag"`
	Value  string         `yaml:"value,omitempty"`
	Symbol *ProfileSymbol `yaml:"symbol,omitempty"`
}

var (
	loadOnce   sync.Once
	loadedAll  []*Profile
	loadedByID map[string]*Profile
	loadErr    error
)

// Overlay dinâmico: perfis SNMP CUSTOM do tenant, entregues pelo backend via
// config-pull (NDM Fase 2). Vivem só em memória; o backend manda o CONJUNTO
// COMPLETO e RegisterDynamicProfiles faz um REPLACE atômico. Os perfis embutidos
// (go:embed) têm precedência sobre os dinâmicos em caso de nome igual — mas o
// backend já rejeita slug custom que colida com builtin, então na prática não há
// colisão.
var (
	dynamicMu   sync.RWMutex
	dynamicByID map[string]*Profile
)

// ParseProfileYAML parseia um YAML de perfil (mesmo formato do embed) e carimba
// o Name. Reusa exatamente o unmarshal do loadAll.
func ParseProfileYAML(name, yamlContent string) (*Profile, error) {
	p := &Profile{}
	if err := yaml.Unmarshal([]byte(yamlContent), p); err != nil {
		return nil, fmt.Errorf("snmp: parse dynamic profile %q: %w", name, err)
	}
	p.Name = name
	return p, nil
}

// RegisterDynamicProfiles substitui atomicamente o overlay dinâmico. Passa o
// CONJUNTO COMPLETO de perfis custom do tenant — o replace é total (criar/editar/
// excluir no backend converge aqui no próximo poll). Passar um map vazio limpa o
// overlay.
func RegisterDynamicProfiles(m map[string]*Profile) {
	dynamicMu.Lock()
	dynamicByID = m
	dynamicMu.Unlock()
}

// loadAll inicializa loadedByID/loadedAll a partir de profiles.FS. Roda
// uma vez via sync.Once.
func loadAll() {
	loadedByID = make(map[string]*Profile)

	entries, err := fs.ReadDir(profiles.FS, ".")
	if err != nil {
		loadErr = fmt.Errorf("snmp: profiles FS ReadDir: %w", err)
		return
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, fname := range names {
		data, err := fs.ReadFile(profiles.FS, fname)
		if err != nil {
			loadErr = fmt.Errorf("snmp: read profile %s: %w", fname, err)
			return
		}
		p := &Profile{}
		if err := yaml.Unmarshal(data, p); err != nil {
			loadErr = fmt.Errorf("snmp: parse profile %s: %w", fname, err)
			return
		}
		p.Name = strings.TrimSuffix(fname, ".yaml")
		loadedByID[p.Name] = p
		loadedAll = append(loadedAll, p)
	}
}

// LoadProfile resolve um perfil pelo nome (sem extensao). Retorna erro
// claro com a lista de validos se o nome nao bate.
func LoadProfile(name string) (*Profile, error) {
	loadOnce.Do(loadAll)
	if loadErr != nil {
		return nil, loadErr
	}
	if p, ok := loadedByID[name]; ok {
		return p, nil
	}
	// Overlay dinâmico (perfis custom do tenant) — precedência menor que o embed.
	dynamicMu.RLock()
	if p, ok := dynamicByID[name]; ok {
		dynamicMu.RUnlock()
		return p, nil
	}
	dynamicMu.RUnlock()
	valid := make([]string, 0, len(loadedByID))
	for k := range loadedByID {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	return nil, fmt.Errorf("snmp: unknown profile %q (valid: %s)", name, strings.Join(valid, ", "))
}

// AllProfiles retorna a slice de todos os perfis bundled. A ordem segue
// a ordem alfabetica do filename.
func AllProfiles() ([]*Profile, error) {
	loadOnce.Do(loadAll)
	if loadErr != nil {
		return nil, loadErr
	}
	// Devolve copia da slice — caller nao deve mutar nossa estrutura. Concatena
	// os perfis dinâmicos (custom do tenant) pra o auto-match (MatchSysObjectID)
	// enxergá-los. Pula dinâmico com nome já presente no embed (embed vence).
	dynamicMu.RLock()
	out := make([]*Profile, 0, len(loadedAll)+len(dynamicByID))
	out = append(out, loadedAll...)
	for name, p := range dynamicByID {
		if _, clash := loadedByID[name]; clash {
			continue
		}
		out = append(out, p)
	}
	dynamicMu.RUnlock()
	return out, nil
}

// MatchSysObjectID resolve o perfil que melhor casa com o sysObjectID
// observado no device. Regra: prefix match (sysOid == base OR sysOid
// comeca com base+".") e em caso de empate o base mais longo vence.
//
// Aceita base com ou sem leading dot e com sufixo opcional ".*" (estilo
// importados) — ambos sao normalizados antes do match.
func MatchSysObjectID(profiles []*Profile, sysOid string) (*Profile, bool) {
	target := strings.TrimPrefix(strings.TrimSpace(sysOid), ".")
	if target == "" {
		return nil, false
	}

	var best *Profile
	var bestLen int
	for _, p := range profiles {
		if p == nil || !p.autoDetectEnabled() {
			continue
		}
		for _, pat := range p.SysObjectID {
			base := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(pat), "."), ".*")
			if base == "" {
				continue
			}
			if target == base || strings.HasPrefix(target, base+".") {
				if len(base) > bestLen {
					best, bestLen = p, len(base)
				}
			}
		}
	}
	return best, best != nil
}

func (p *Profile) autoDetectEnabled() bool {
	return p.AutoDetect == nil || *p.AutoDetect
}

// Collect executa o perfil contra um Client conectado, emitindo metricas
// segundo o YAML. staticTags vem do CheckConfig.static_tags + tags
// adicionadas pelo caller; merge: staticTags < profile.MetricTags <
// table.metric_tags (precedencia da direita).
//
// Comportamento de erro: erros pontuais (uma coluna ausente, uma metrica
// nao-numerica) viram skip silencioso. So retorna erro se TODOS os OIDs
// scalares falharem ou se nenhuma metrica conseguir ser emitida (sinaliza
// problema de rede/credencial, nao mismatch de perfil).
func (p *Profile) Collect(ctx context.Context, c *Client, hostID string, staticTags map[string]string) ([]*collectorv1.Metric, error) {
	if p == nil {
		return nil, errors.New("snmp: Profile nil")
	}
	if c == nil {
		return nil, errors.New("snmp: Client nil")
	}

	// Tags estaticas do perfil (valor fixo, sem Symbol).
	profileTags := make(map[string]string)
	for _, t := range p.MetricTags {
		if t.Symbol == nil && t.Value != "" && t.Tag != "" {
			profileTags[t.Tag] = t.Value
		}
	}

	now := timestamppb.Now()
	var out []*collectorv1.Metric
	scalarAttempts := 0
	scalarSuccess := 0

	for _, m := range p.Metrics {
		switch {
		case m.Symbol != nil:
			scalarAttempts++
			val, ok := getScalar(ctx, c, m.Symbol.OID)
			if !ok {
				continue
			}
			scalarSuccess++
			out = append(out, newMetric(now, hostID, canonMetricName(m.Symbol.OID, m.Symbol.Name), applyScale(val, m.Symbol.Scale), mergeTags(staticTags, profileTags, nil)))

		case m.Table != nil:
			rows, err := WalkTable(ctx, c, m.Table.OID)
			if err != nil {
				// Tabela toda falhou — pula, mas nao aborta o perfil.
				continue
			}
			for rowIndex, row := range rows {
				rowTags := resolveTableTags(row, m.MetricTags)
				rowTags["row_index"] = rowIndex
				// Filtro declarativo: descarta rows que não interessam (ex.: portas
				// LAN de ONU num OLT) antes de virar métrica — enxuga a coleta.
				if m.Filter != nil && !m.Filter.keep(rowTags) {
					continue
				}
				// Enriquecimento GENÉRICO do hrStorageTable (HOST-RESOURCES-MIB,
				// RFC 2790): a BulkWalk já trouxe TODAS as colunas da row, então
				// acrescentamos storage_type (RAM/disco/flash...) e storage_descr, e
				// pegamos o fator de bloco pra converter size/used de blocos → bytes —
				// mesmo que o profile só declare size/used (como fazem quase todos, do
				// Mikrotik ao Cisco). Vale pra QUALQUER fabricante que ande nesse OID
				// padrão. É no-op em qualquer outra tabela.
				storageFactor := enrichHrStorageRow(m.Table.OID, row, rowTags)
				seen := make(map[string]bool, len(m.Symbols))
				for _, sym := range m.Symbols {
					pdu, ok := findRowPDU(row, sym.OID)
					if !ok {
						continue
					}
					val, ok := PduFloat(pdu)
					if !ok {
						continue
					}
					name := canonMetricName(sym.OID, sym.Name)
					if seen[name] {
						continue // HC vs 32-bit colidem no mesmo canônico — 1 por row
					}
					seen[name] = true
					scaled := applyScale(val, sym.Scale)
					// hrStorageSize/Used vêm em BLOCOS; × unidade de alocação = bytes reais.
					if storageFactor != 1 && isHrStorageAmount(sym.OID) {
						scaled *= storageFactor
					}
					out = append(out, newMetric(now, hostID, name, scaled, mergeTags(staticTags, profileTags, rowTags)))
				}
			}
		}
	}

	// Novo formato: discovery_rules. Cada rule:
	//   1) walk keys → map[rowSuffix]map[label]value (labels da row)
	//   2) walk items → para cada PDU, lookup labels pelo rowSuffix, emit
	// Falha de uma rule = skip silencioso (paralela ao tratamento de tabelas).
	for _, rule := range p.DiscoveryRules {
		ruleMetrics := executeDiscoveryRule(ctx, c, &rule, now, hostID, staticTags, profileTags)
		out = append(out, ruleMetrics...)
	}

	// Heuristica de erro de rede: se tentou escalares e TODOS falharam E nao
	// produziu nada de tabela, sinaliza erro para o caller (provavel device
	// offline, community errada, etc).
	if scalarAttempts > 0 && scalarSuccess == 0 && len(out) == 0 {
		return nil, fmt.Errorf("snmp: profile %s: nenhum OID respondeu", p.Name)
	}

	return out, nil
}

// CollectDeviceMetadata resolve a identidade do device (vendor/model/serial/OS…):
//  1. BASE derivada de OIDs padrão (sysDescr, sysObjectID, ENTITY-MIB) — vale pra
//     QUALQUER device, mesmo sem bloco metadata no profile (a maioria dos 174
//     alguns profiles só declaram `type:`, sem identidade).
//  2. OVERLAY do bloco metadata do profile, que é AUTORITATIVO (sobrepõe o
//     derivado): valor estático direto, ou GET do OID → string.
//
// Fail-soft em tudo: campo que não responder é omitido.
func (p *Profile) CollectDeviceMetadata(ctx context.Context, c *Client) map[string]string {
	out := deriveStandardMetadata(ctx, c)
	if p.Metadata == nil {
		return out
	}
	for field, mf := range p.Metadata.Device {
		if field == "" {
			continue
		}
		if mf.Value != "" && mf.Symbol == nil {
			out[field] = mf.Value
			continue
		}
		if mf.Symbol == nil || mf.Symbol.OID == "" {
			continue
		}
		pdus, err := c.Get(ctx, []string{mf.Symbol.OID})
		if err != nil || len(pdus) == 0 {
			continue
		}
		s := strings.TrimSpace(pduString(pdus[0]))
		if s != "" {
			out[field] = s
		}
	}
	return out
}

// OIDs padrão de identidade (SNMPv2-MIB + ENTITY-MIB) — respondidos por
// praticamente qualquer device SNMP, independentemente de profile de vendor.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"         // sysDescr
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"         // sysObjectID
	oidEntModel    = "1.3.6.1.2.1.47.1.1.1.1.13" // entPhysicalModelName
	oidEntSerial   = "1.3.6.1.2.1.47.1.1.1.1.11" // entPhysicalSerialNum
	oidEntSoftware = "1.3.6.1.2.1.47.1.1.1.1.10" // entPhysicalSoftwareRev
)

var reVersion = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// deriveStandardMetadata deriva a identidade do device de OIDs padrão. Serve de
// BASE (o profile sobrepõe). Campos: sys_object_id + vendor (do enterprise
// number), os_name/version (de sysDescr), model/serial_number/version (do
// ENTITY-MIB). Fail-soft: o que não responder fica de fora.
func deriveStandardMetadata(ctx context.Context, c *Client) map[string]string {
	out := make(map[string]string)
	if pdus, err := c.Get(ctx, []string{oidSysDescr, oidSysObjectID}); err == nil {
		for _, pd := range pdus {
			name := strings.TrimPrefix(pd.Name, ".")
			switch {
			case strings.HasPrefix(name, "1.3.6.1.2.1.1.1"): // sysDescr
				if osn, osv := parseSysDescr(pduString(pd)); osn != "" {
					out["os_name"] = osn
					if osv != "" {
						out["version"] = osv
					}
				}
			case strings.HasPrefix(name, "1.3.6.1.2.1.1.2"): // sysObjectID
				soid := strings.TrimSpace(pduString(pd))
				if soid != "" {
					out["sys_object_id"] = soid
					if v := vendorFromSysObjectID(soid); v != "" {
						out["vendor"] = v
					}
				}
			}
		}
	}
	// ENTITY-MIB: colunas walked, primeira linha não-vazia (o chassi é a 1ª
	// entidade física na maioria dos devices). Autoritativo quando responde.
	if m := walkFirstNonEmpty(ctx, c, oidEntModel); m != "" {
		out["model"] = m
	}
	if s := walkFirstNonEmpty(ctx, c, oidEntSerial); s != "" {
		out["serial_number"] = s
	}
	if sw := walkFirstNonEmpty(ctx, c, oidEntSoftware); sw != "" {
		out["version"] = sw // ENTITY software rev é mais preciso que o parse do sysDescr
	}
	return out
}

// walkFirstNonEmpty faz WalkAll numa coluna e devolve o primeiro valor string
// não-vazio. Vazio em erro ou coluna sem resposta.
func walkFirstNonEmpty(ctx context.Context, c *Client, root string) string {
	pdus, err := c.WalkAll(ctx, root)
	if err != nil {
		return ""
	}
	for _, pd := range pdus {
		if s := strings.TrimSpace(pduString(pd)); s != "" {
			return s
		}
	}
	return ""
}

// parseSysDescr extrai (os_name, os_version) do sysDescr pra vendors comuns.
// Heurística conservadora: só reconhece padrões conhecidos; senão devolve vazio
// (o ENTITY-MIB / profile preenchem o resto).
func parseSysDescr(d string) (osName, osVersion string) {
	d = strings.TrimSpace(d)
	if d == "" {
		return "", ""
	}
	ver := reVersion.FindString(d)
	l := strings.ToLower(d)
	switch {
	case strings.Contains(l, "routeros"):
		return "RouterOS", ver
	case strings.Contains(l, "ios xe"):
		return "IOS XE", ver
	case strings.Contains(l, "nx-os"):
		return "NX-OS", ver
	case strings.Contains(l, "cisco ios"), strings.Contains(l, "cisco internetwork operating system"):
		return "IOS", ver
	case strings.Contains(l, "junos"):
		return "Junos", ver
	case strings.Contains(l, "arubaos"):
		return "ArubaOS", ver
	case strings.Contains(l, "fortios"), strings.Contains(l, "fortigate"):
		return "FortiOS", ver
	case strings.Contains(l, "vyos"):
		return "VyOS", ver
	case strings.Contains(l, "linux"):
		return "Linux", ver
	}
	return "", ""
}

// vendorFromSysObjectID mapeia o enterprise number (1.3.6.1.4.1.<N>…) pro nome
// do vendor. Só os IANA PEN de rede mais comuns (conservador).
func vendorFromSysObjectID(oid string) string {
	const ent = "1.3.6.1.4.1."
	o := strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if !strings.HasPrefix(o, ent) {
		return ""
	}
	n := o[len(ent):]
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i]
	}
	switch n {
	case "9":
		return "Cisco"
	case "2011":
		return "Huawei"
	case "14988":
		return "MikroTik"
	case "2636":
		return "Juniper"
	case "674":
		return "Dell"
	case "11":
		return "HP"
	case "25506":
		return "H3C"
	case "12356":
		return "Fortinet"
	case "14823":
		return "Aruba"
	case "1916":
		return "Extreme"
	case "1991":
		return "Brocade"
	case "3375":
		return "F5"
	case "8072":
		return "Net-SNMP"
	case "2352":
		return "Nokia"
	}
	return ""
}

// executeDiscoveryRule walks keys, walks items, joins por rowSuffix e devolve
// as métricas resultantes. Erros em walks individuais são tolerados (skip
// silencioso, paralelo ao Collect das ProfileMetric.Table).
func executeDiscoveryRule(
	ctx context.Context,
	c *Client,
	rule *ProfileDiscoveryRule,
	now *timestamppb.Timestamp,
	hostID string,
	staticTags, profileTags map[string]string,
) []*collectorv1.Metric {
	// 1) keys: rowSuffix → label → value
	labelsByRow := map[string]map[string]string{}
	for _, k := range rule.Keys {
		if k.Label == "" || k.OID == "" {
			continue
		}
		pdus, err := c.WalkAll(ctx, k.OID)
		if err != nil {
			continue
		}
		for _, pdu := range pdus {
			suffix := oidSuffix(pdu.Name, k.OID)
			if suffix == "" {
				continue
			}
			row := labelsByRow[suffix]
			if row == nil {
				row = make(map[string]string, len(rule.Keys))
				labelsByRow[suffix] = row
			}
			row[k.Label] = pduString(pdu)
		}
	}

	// 2) items: cada PDU vira 1 métrica. Labels = keys da row + static_tags.
	// O nome é normalizado pelo OID (canonMetricName) — perfis importados batizam
	// as colunas IF-MIB como community.<vendor>.net_if_*; viram snmp.if.* canônico.
	// emitted dedup por (nome canônico, row): se o perfil trouxer HC e 32-bit da
	// mesma coluna, fica só a 1ª (evita série duplicada).
	var out []*collectorv1.Metric
	emitted := make(map[string]bool)
	for _, item := range rule.Items {
		if item.Name == "" || item.OID == "" {
			continue
		}
		name := canonMetricName(item.OID, item.Name)
		pdus, err := c.WalkAll(ctx, item.OID)
		if err != nil {
			continue
		}
		for _, pdu := range pdus {
			val, ok := PduFloat(pdu)
			if !ok {
				continue
			}
			suffix := oidSuffix(pdu.Name, item.OID)
			if emitted[name+"\x00"+suffix] {
				continue
			}
			emitted[name+"\x00"+suffix] = true
			rowTags := make(map[string]string, len(rule.StaticTags)+8)
			for k, v := range rule.StaticTags {
				rowTags[k] = v
			}
			if suffix != "" {
				rowTags["row_index"] = suffix
			}
			if row, ok := labelsByRow[suffix]; ok {
				for lbl, v := range row {
					rowTags[lbl] = v
				}
			}
			out = append(out, newMetric(now, hostID, name, applyScale(val, item.Scale), mergeTags(staticTags, profileTags, rowTags)))
		}
	}
	return out
}

// oidSuffix devolve a parte da PDU OID depois do prefix (sem leading dot).
// Ex: oidSuffix(".1.3.6.1.2.1.2.2.1.10.42", "1.3.6.1.2.1.2.2.1.10") → "42".
// Retorna "" se PDU OID não estiver dentro do prefix.
func oidSuffix(pduOID, prefix string) string {
	p := strings.TrimPrefix(pduOID, ".")
	r := strings.TrimPrefix(prefix, ".")
	if !strings.HasPrefix(p, r+".") {
		if p == r {
			return ""
		}
		return ""
	}
	return p[len(r)+1:]
}

// applyScale multiplica o valor bruto pelo fator do perfil — ex.: 0.01 pra
// converter centi-dBm → dBm ou centi-% → %, como faz o template community do
// Fiberhome. scale == 0 significa "sem escala" (valor inalterado).
func applyScale(v, scale float64) float64 {
	if scale == 0 {
		return v
	}
	return v * scale
}

// getScalar faz Get de um OID escalar. Tenta o OID como está; se não vier valor
// e o OID não terminar em ".0", tenta o instance ".0". Isso porque os perfis do
// Alguns catálogos escrevem escalares SEM o ".0" (ex. mtxrHlCpuTemperature = .3.6), mas o
// SNMP exige o ".0" no GET de escalar — nossos perfis hand-curated já põem o ".0".
// canonMetricName usa o OID do PERFIL (sem .0), então o mapa canônico continua batendo.
func getScalar(ctx context.Context, c *Client, oid string) (float64, bool) {
	if v, ok := getScalarOnce(ctx, c, oid); ok {
		return v, true
	}
	if !strings.HasSuffix(oid, ".0") {
		if v, ok := getScalarOnce(ctx, c, oid+".0"); ok {
			return v, true
		}
	}
	return 0, false
}

func getScalarOnce(ctx context.Context, c *Client, oid string) (float64, bool) {
	pdus, err := c.Get(ctx, []string{oid})
	if err != nil || len(pdus) == 0 {
		return 0, false
	}
	return PduFloat(pdus[0])
}

// OIDs padrão do hrStorageTable (HOST-RESOURCES-MIB, RFC 2790). Universais entre
// fabricantes — Mikrotik, Cisco, Fortinet, Linux e qualquer um que exponha a MIB
// andam exatamente nestes OIDs.
const (
	hrStorageTableOID = "1.3.6.1.2.1.25.2.3"
	hrStorageTypeCol  = "1.3.6.1.2.1.25.2.3.1.2" // hrStorageType (OID → HOST-RESOURCES-TYPES)
	hrStorageDescrCol = "1.3.6.1.2.1.25.2.3.1.3" // hrStorageDescr (texto)
	hrStorageAllocCol = "1.3.6.1.2.1.25.2.3.1.4" // hrStorageAllocationUnits (bytes por bloco)
	hrStorageSizeCol  = "1.3.6.1.2.1.25.2.3.1.5" // hrStorageSize (em blocos)
	hrStorageUsedCol  = "1.3.6.1.2.1.25.2.3.1.6" // hrStorageUsed (em blocos)
)

// enrichHrStorageRow, quando a tabela é o hrStorageTable padrão, acrescenta à row
// os rótulos storage_type (ram/fixed_disk/flash...) e storage_descr a partir das
// colunas que a BulkWalk já trouxe, e devolve o FATOR de bloco (unidade de
// alocação em bytes) pra converter size/used de blocos → bytes reais. Fora do
// hrStorage devolve 1 (no-op). Isso resolve, de uma vez e pra todo fabricante,
// (a) "1 MB" no lugar de "1 GB" (blocos lidos como bytes) e (b) RAM vs disco
// decidido pelo TIPO (código de máquina), não por casar texto do descritor.
func enrichHrStorageRow(tableOID string, row map[string]gosnmp.SnmpPDU, rowTags map[string]string) float64 {
	if strings.TrimPrefix(strings.TrimSpace(tableOID), ".") != hrStorageTableOID {
		return 1
	}
	if pdu, ok := findRowPDU(row, hrStorageTypeCol); ok {
		if t := hrStorageTypeName(pduString(pdu)); t != "" {
			rowTags["storage_type"] = t
		}
	}
	if pdu, ok := findRowPDU(row, hrStorageDescrCol); ok {
		if s := strings.TrimSpace(pduString(pdu)); s != "" {
			rowTags["storage_descr"] = s
		}
	}
	if pdu, ok := findRowPDU(row, hrStorageAllocCol); ok {
		if u, ok := PduFloat(pdu); ok && u > 0 {
			return u
		}
	}
	return 1
}

// isHrStorageAmount diz se o OID é hrStorageSize/Used (as quantidades em blocos
// que precisam × unidade de alocação pra virar bytes).
func isHrStorageAmount(oid string) bool {
	o := strings.TrimPrefix(oid, ".")
	return o == hrStorageSizeCol || o == hrStorageUsedCol
}

// hrStorageTypeName mapeia o valor de hrStorageType (que é um OID apontando pra
// HOST-RESOURCES-TYPES, .1.3.6.1.2.1.25.2.1.X) a um rótulo amigável. É o sinal
// DETERMINÍSTICO de "isto é RAM" vs "isto é disco" — bem melhor que casar o texto
// do descritor ("main memory"), que varia por fabricante/idioma.
func hrStorageTypeName(typeOID string) string {
	switch strings.TrimPrefix(strings.TrimSpace(typeOID), ".") {
	case "1.3.6.1.2.1.25.2.1.1":
		return "other"
	case "1.3.6.1.2.1.25.2.1.2":
		return "ram"
	case "1.3.6.1.2.1.25.2.1.3":
		return "virtual_memory"
	case "1.3.6.1.2.1.25.2.1.4":
		return "fixed_disk"
	case "1.3.6.1.2.1.25.2.1.5":
		return "removable_disk"
	case "1.3.6.1.2.1.25.2.1.6":
		return "floppy_disk"
	case "1.3.6.1.2.1.25.2.1.7":
		return "compact_disc"
	case "1.3.6.1.2.1.25.2.1.8":
		return "ram_disk"
	case "1.3.6.1.2.1.25.2.1.9":
		return "flash_memory"
	case "1.3.6.1.2.1.25.2.1.10":
		return "network_disk"
	default:
		return ""
	}
}

// findRowPDU localiza a PDU correspondente a uma coluna em uma row.
// Aceita match com OU sem leading dot.
func findRowPDU(row map[string]gosnmp.SnmpPDU, colOID string) (gosnmp.SnmpPDU, bool) {
	want := strings.TrimPrefix(colOID, ".")
	for k, v := range row {
		if strings.TrimPrefix(k, ".") == want {
			return v, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

// resolveTableTags monta tags dinamicas pra uma row. Cada metric_tag com
// Symbol busca a PDU da coluna nessa row e converte para string.
func resolveTableTags(row map[string]gosnmp.SnmpPDU, tags []ProfileMetricTag) map[string]string {
	out := make(map[string]string)
	for _, t := range tags {
		if t.Tag == "" {
			continue
		}
		if t.Value != "" && t.Symbol == nil {
			out[t.Tag] = t.Value
			continue
		}
		if t.Symbol == nil {
			continue
		}
		pdu, ok := findRowPDU(row, t.Symbol.OID)
		if !ok {
			continue
		}
		out[t.Tag] = pduString(pdu)
	}
	return out
}

// pduString converte uma PDU para string adequada pra tag. OctetString
// vira string; numericos viram fmt.Sprintf("%d"); resto vira fmt.Sprintf("%v").
func pduString(p gosnmp.SnmpPDU) string {
	// OIDs que o device não implementa voltam como NoSuchObject/NoSuchInstance/
	// EndOfMibView (ou Null) com Value nil. Sem tratar, o default cairia em
	// fmt.Sprintf("%v", nil) = a string literal "<nil>", que vazava pro inventário
	// (Modelo/Serial/OS = "<nil>"). Vazio é o correto: o campo fica de fora.
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return ""
	}
	switch v := p.Value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// mergeTags monta um map final aplicando precedencia: staticTags <
// profileTags < tableTags (right wins).
func mergeTags(static, profile, table map[string]string) map[string]string {
	out := make(map[string]string, len(static)+len(profile)+len(table))
	for k, v := range static {
		out[k] = v
	}
	for k, v := range profile {
		out[k] = v
	}
	for k, v := range table {
		out[k] = v
	}
	return out
}

// newMetric monta um collectorv1.Metric com Source "snmp".
func newMetric(ts *timestamppb.Timestamp, hostID, name string, val float64, tags map[string]string) *collectorv1.Metric {
	return &collectorv1.Metric{
		Time:       ts,
		HostId:     hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "snmp",
	}
}

// oidCanonical mapeia OIDs padrão (universais entre fabricantes) ao nome CANÔNICO
// snmp.* que o backend Telvyn consulta. Normalizar por OID (não por texto) faz o
// sinal acender em QUALQUER perfil que ande no OID certo — independente de como o
// perfil batizou a métrica.
//
//   - IF-MIB (tráfego/erros/status): IfaceMetricsReader, InterfaceRegistryJob,
//     DeviceLensService leem snmp.if.*. Perfis importados batizavam como
//     community.<vendor>.net_if_* (backend NÃO lia) — a normalização conserta.
//   - HOST-RESOURCES / UCD / SNMPv2 (CPU/memória/uptime): DeviceMetricsTab e o
//     MonitorDrawer leem snmp.hr.processor_load, snmp.hr.storage_used,
//     snmp.mem.avail_kb, snmp.sys.uptime. Os perfis importados usam esses
//     mesmos OIDs padrão mas batizam como hrProcessorLoad/cpu.usage/memory.free —
//     normalizar faz CPU/memória/uptime acenderem em todo fabricante.
//
// É no-op pros perfis hand-curated, que já emitem o canônico nesses mesmos OIDs.
// Octets de 32 e 64 bits (HC) mapeiam pro mesmo canônico; o dedup por-row evita
// série duplicada quando o perfil traz os dois.
var oidCanonical = map[string]string{
	// --- IF-MIB (interface) ---
	"1.3.6.1.2.1.2.2.1.10":    "snmp.if.in_octets",    // ifInOctets (32-bit)
	"1.3.6.1.2.1.31.1.1.1.6":  "snmp.if.in_octets",    // ifHCInOctets (64-bit)
	"1.3.6.1.2.1.2.2.1.16":    "snmp.if.out_octets",   // ifOutOctets
	"1.3.6.1.2.1.31.1.1.1.10": "snmp.if.out_octets",   // ifHCOutOctets
	"1.3.6.1.2.1.2.2.1.14":    "snmp.if.in_errors",    // ifInErrors
	"1.3.6.1.2.1.2.2.1.20":    "snmp.if.out_errors",   // ifOutErrors
	"1.3.6.1.2.1.2.2.1.13":    "snmp.if.in_discards",  // ifInDiscards
	"1.3.6.1.2.1.2.2.1.19":    "snmp.if.out_discards", // ifOutDiscards
	"1.3.6.1.2.1.2.2.1.8":     "snmp.if.oper_status",  // ifOperStatus
	"1.3.6.1.2.1.2.2.1.7":     "snmp.if.admin_status", // ifAdminStatus
	"1.3.6.1.2.1.2.2.1.3":     "snmp.if.type",         // ifType
	"1.3.6.1.2.1.31.1.1.1.15": "snmp.if.high_speed",   // ifHighSpeed
	"1.3.6.1.2.1.2.2.1.5":     "snmp.if.speed",        // ifSpeed
	"1.3.6.1.2.1.2.2.1.4":     "snmp.if.mtu",          // ifMtu (bytes, escalar por interface)
	// Contadores de pacotes por tipo (ifXTable, 64-bit). ATENÇÃO: .10 é ifHCOutOctets,
	// então ifHCOutUcastPkts é .11 (não .10).
	"1.3.6.1.2.1.31.1.1.1.7":  "snmp.if.in_ucast_packets",  // ifHCInUcastPkts
	"1.3.6.1.2.1.31.1.1.1.8":  "snmp.if.in_mcast_packets",  // ifHCInMulticastPkts
	"1.3.6.1.2.1.31.1.1.1.9":  "snmp.if.in_bcast_packets",  // ifHCInBroadcastPkts
	"1.3.6.1.2.1.31.1.1.1.11": "snmp.if.out_ucast_packets", // ifHCOutUcastPkts
	"1.3.6.1.2.1.31.1.1.1.12": "snmp.if.out_mcast_packets", // ifHCOutMulticastPkts
	"1.3.6.1.2.1.31.1.1.1.13": "snmp.if.out_bcast_packets", // ifHCOutBroadcastPkts

	// --- HOST-RESOURCES-MIB (CPU + armazenamento, universal) ---
	"1.3.6.1.2.1.25.3.3.1.2": "snmp.hr.processor_load", // hrProcessorLoad (% por core)
	"1.3.6.1.2.1.25.2.3.1.5": "snmp.hr.storage_size",   // hrStorageSize (alloc units)
	"1.3.6.1.2.1.25.2.3.1.6": "snmp.hr.storage_used",   // hrStorageUsed (alloc units)

	// --- UCD-SNMP-MIB (memória real, em KB) ---
	"1.3.6.1.4.1.2021.4.5.0": "snmp.mem.total_kb", // memTotalReal
	"1.3.6.1.4.1.2021.4.6.0": "snmp.mem.avail_kb", // memAvailReal

	// --- SNMPv2-MIB (uptime) ---
	"1.3.6.1.2.1.1.3.0": "snmp.sys.uptime", // sysUpTime (centésimos de s)

	// --- MIKROTIK-MIB (temperatura, °C) ---
	// O profile mikrotik-router lê os OIDs corretos de temperatura
	// (mtxrHlCpuTemperature .3.6 e mtxrHlTemperature .3.10) mas os batiza com o
	// nome da MIB. Canonizar pra mikrotik.health.temp_* faz o DeviceMetricsTab
	// (filtro mikrotik_health_temp.*) mostrar no widget de Temperatura.
	"1.3.6.1.4.1.14988.1.1.3.6":  "mikrotik.health.temp_cpu",    // mtxrHlCpuTemperature
	"1.3.6.1.4.1.14988.1.1.3.10": "mikrotik.health.temp_system", // mtxrHlTemperature
}

// canonMetricName devolve o nome canônico snmp.* quando o OID é conhecido
// (IF-MIB, HOST-RESOURCES, UCD, SNMPv2); senão devolve o nome do perfil inalterado.
func canonMetricName(oid, fallback string) string {
	if c, ok := oidCanonical[strings.TrimPrefix(oid, ".")]; ok {
		return c
	}
	return fallback
}
