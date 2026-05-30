package tools

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// MikrotikDiscoverTopology runs `/ip neighbor print detail without-paging`
// over SSH on a RouterOS device and emits TopologyEdgeReport-shaped entries
// in result["topology_edges"]. The scheduler picks those up and forwards via
// the ReportTopology RPC (separate path from result["metrics"]).
//
// args (server-merged from CredentialVault):
//
//	host          string  required  IP/hostname
//	port          number  optional  default 22
//	username      string  required  SSH user with read perms
//	password      string  optional  } exactly one
//	private_key   string  optional  } of these two
//	known_host    string  optional  known_hosts line for host key verification
//	timeout       number  optional  seconds, default 30
//	local_host_id string  optional  identity at the server inventory; if absent
//	                                we fall back to host
//
// Why a dedicated tool (not ssh.exec + parser elsewhere): RouterOS output is
// structured and the parsing only matters here — keeping it co-located with
// the SSH invocation avoids a second roundtrip for the operator to wire two
// jobs (run+parse). Future vendors (cisco_ios.discover_topology,
// junos.discover_topology, fortios.discover_topology) follow the same shape.
type MikrotikDiscoverTopology struct{}

func (MikrotikDiscoverTopology) Name() string { return "mikrotik.discover_topology" }

func (MikrotikDiscoverTopology) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	host, err := requireString(args, "host")
	if err != nil {
		return nil, err
	}
	user, err := requireString(args, "username")
	if err != nil {
		// Aceita "user" como alias (ssh.exec usa "user")
		if u, ok := args["user"].(string); ok && u != "" {
			user = u
		} else {
			return nil, err
		}
	}
	port := optInt(args, "port", 22)
	timeoutSec := optInt(args, "timeout", 30)
	localHostId, _ := args["local_host_id"].(string)
	if localHostId == "" {
		localHostId = host
	}

	authMethods, err := buildAuthMethods(args)
	if err != nil {
		return nil, err
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if khLine, ok := args["known_host"].(string); ok && khLine != "" {
		_, _, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(khLine))
		if err != nil {
			return nil, fmt.Errorf("parse known_host: %w", err)
		}
		hostKeyCallback = ssh.FixedHostKey(pubKey)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshDialTimeout,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialErrCh := make(chan error, 1)
	var client *ssh.Client
	go func() {
		var derr error
		client, derr = ssh.Dial("tcp", addr, cfg)
		dialErrCh <- derr
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case derr := <-dialErrCh:
		if derr != nil {
			return nil, fmt.Errorf("ssh dial %s: %w", addr, derr)
		}
	}
	defer client.Close()

	start := time.Now()
	cmdTimeout := time.Duration(timeoutSec) * time.Second

	// Step 1: inventário local (identity, interfaces+MACs, IPs).
	// Necessário pra filtrar self-loops por identity E por MAC, e pra
	// correlacionar ARP/route entries com a interface local exata.
	localInv := gatherLocalInventory(ctx, client, cmdTimeout)
	if localHostId == "" && localInv.identity != "" {
		// Operador não passou local_host_id explícito → usa identity como fallback
		localHostId = localInv.identity
	}

	// Step 2: múltiplas fontes de vizinhos.
	// LLDP/CDP/MNDP é a fonte primária (mais rica). ARP descobre hosts
	// L2 que não anunciam LLDP (CPEs/modems/OLTs). Routes capturam
	// gateways/next-hops L3. BGP peers cobrem peerings cross-AS.
	var allEdges []map[string]any
	sourceCounts := map[string]int{}

	if neighborOut, err := runCommand(ctx, client, "/ip neighbor print detail without-paging", cmdTimeout); err == nil {
		es := parseMikrotikNeighborDetail(neighborOut, localHostId)
		sourceCounts["neighbor"] = len(es)
		allEdges = append(allEdges, es...)
	}
	if arpOut, err := runCommand(ctx, client, "/ip arp print detail without-paging", cmdTimeout); err == nil {
		es := buildEdgesFromArp(arpOut, localInv, localHostId)
		sourceCounts["arp"] = len(es)
		allEdges = append(allEdges, es...)
	}
	// Sem filter `dynamic=yes` — pegamos rotas estáticas também (default route
	// configurada manualmente é o gateway pra Internet/upstream).
	if routeOut, err := runCommand(ctx, client, "/ip route print detail without-paging where active=yes", cmdTimeout); err == nil {
		es := buildEdgesFromRoutes(routeOut, localInv, localHostId)
		sourceCounts["route"] = len(es)
		allEdges = append(allEdges, es...)
	}
	// BGP pode não estar configurado (RouterOS retorna erro). Try-and-skip.
	if bgpOut, err := runCommand(ctx, client, "/routing bgp peer print detail without-paging", cmdTimeout); err == nil && strings.TrimSpace(bgpOut) != "" {
		es := buildEdgesFromBgpPeers(bgpOut, localHostId)
		sourceCounts["bgp"] = len(es)
		allEdges = append(allEdges, es...)
	}

	durationMs := time.Since(start).Milliseconds()

	// Filtra self-loops (identity OR MAC bate com local), depois dedup
	// por MAC remoto mantendo maior confidence.
	preFilter := len(allEdges)
	allEdges = filterSelfLoopsAdvanced(allEdges, localInv)
	selfLoopsDropped := preFilter - len(allEdges)
	preDedup := len(allEdges)
	edges := dedupByRemoteMac(allEdges)
	dedupedDropped := preDedup - len(edges)

	commentedAddrs := 0
	for _, a := range localInv.addresses {
		if strings.TrimSpace(a.comment) != "" {
			commentedAddrs++
		}
	}

	return map[string]any{
		"topology_edges":           edges,
		"local_identity":           localInv.identity,
		"local_iface_count":        float64(len(localInv.interfaces)),
		"local_address_count":      float64(len(localInv.addresses)),
		"local_address_commented":  float64(commentedAddrs),
		"source_counts":            toFloatMap(sourceCounts),
		"self_loops_dropped":       float64(selfLoopsDropped),
		"deduped_dropped":          float64(dedupedDropped),
		"duration_ms":              float64(durationMs),
	}, nil
}

func toFloatMap(in map[string]int) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = float64(v)
	}
	return out
}

// localInventory é o que sabemos do equipamento ANTES de processar vizinhos.
// Carregado no início pra permitir filtros de self-loop e correlação
// IP↔interface ao montar edges via ARP/route.
type localInventory struct {
	identity  string
	macs      map[string]bool         // MACs locais (lowercase, com ":")
	interfaces map[string]ifaceInfo   // by interface name
	addresses []addressInfo
}

type ifaceInfo struct {
	name       string
	macAddress string
	ifaceType  string  // "ether", "sfp", "vlan", "bonding", "bridge", "ppp", ...
	mtu        int
}

type addressInfo struct {
	address         string // "192.168.1.5/24"
	network         string // "192.168.1.0"
	interfaceName   string // logical interface (vlan100, bonding-OLT-INTELBRAS, ...)
	actualInterface string // physical underlying iface (ether2 quando interface=vlan100)
	comment         string // operador-defined ("Uplink-CGNAT", "PEERING-LACNIC", "OLT-INTELBRAS-PON1")
	disabled        bool   // X flag no RouterOS — endereço desabilitado
}

func gatherLocalInventory(ctx context.Context, client *ssh.Client, timeout time.Duration) localInventory {
	inv := localInventory{
		macs:       map[string]bool{},
		interfaces: map[string]ifaceInfo{},
	}
	if out, err := runCommand(ctx, client, "/system identity print without-paging", timeout); err == nil {
		inv.identity = parseSystemIdentity(out)
	}
	if out, err := runCommand(ctx, client, "/interface print detail without-paging", timeout); err == nil {
		inv.interfaces = parseInterfaceDetail(out)
		for _, iface := range inv.interfaces {
			if mac := strings.ToLower(strings.TrimSpace(iface.macAddress)); mac != "" {
				inv.macs[mac] = true
			}
		}
	}
	if out, err := runCommand(ctx, client, "/ip address print detail without-paging", timeout); err == nil {
		inv.addresses = parseAddressDetail(out)
	}
	return inv
}

// parseInterfaceDetail extrai o que precisamos do output de
// `/interface print detail`. Cada bloco vira um ifaceInfo.
func parseInterfaceDetail(output string) map[string]ifaceInfo {
	out := map[string]ifaceInfo{}
	for _, blk := range splitNeighborBlocks(output) {
		f := parseKeyValueFields(blk)
		name := f["name"]
		if name == "" {
			continue
		}
		mtu, _ := strconv.Atoi(f["mtu"])
		out[name] = ifaceInfo{
			name:       name,
			macAddress: strings.ToLower(f["mac-address"]),
			ifaceType:  f["type"],
			mtu:        mtu,
		}
	}
	return out
}

// parseAddressDetail extrai endereços IP locais com a interface, a interface
// física subjacente, e o comentário do operador. O comentário tipicamente
// descreve o papel do link ("Uplink-CGNAT", "PEERING-LACNIC", "OLT-PON1") e
// é uma das poucas fontes de informação semântica que conseguimos pegar
// sem inventário externo — preservamos pra enriquecer edges ARP/route.
//
// Formato típico:
//
//	 0   address=192.168.1.5/24 network=192.168.1.0 interface=ether1 actual-interface=ether1
//	 1 D address=10.10.0.1/30 network=10.10.0.0 interface=vlan100 actual-interface=ether2 comment="Uplink-Borda"
//	 2 X address=10.99.0.1/24 network=10.99.0.0 interface=ether9 actual-interface=ether9
//
// `D` = dynamic, `X` = disabled. Skipamos disabled (não tem tráfego real).
func parseAddressDetail(output string) []addressInfo {
	out := []addressInfo{}
	for _, blk := range splitNeighborBlocks(output) {
		// `X` flag aparece no header do bloco, antes do primeiro `key=`.
		// stripLeadingIndex devora isso então precisamos olhar pro bloco cru.
		disabled := blockHasFlag(blk, 'X')
		if disabled {
			continue
		}
		f := parseKeyValueFields(blk)
		if f["address"] == "" {
			continue
		}
		out = append(out, addressInfo{
			address:         f["address"],
			network:         f["network"],
			interfaceName:   pickFirstNonEmpty(f["interface"], f["actual-interface"]),
			actualInterface: f["actual-interface"],
			comment:         f["comment"],
		})
	}
	return out
}

// blockHasFlag inspeciona o "header" de um bloco RouterOS (porção antes
// do primeiro `key=`) procurando uma flag de letra única. RouterOS
// imprime flags como letras separadas por espaço entre o índice e os
// pares key=value: ` 1 D X address=...`. Útil pra detectar `X` (disabled),
// `D` (dynamic), `I` (invalid) etc.
func blockHasFlag(block string, flag byte) bool {
	// Header é tudo até o primeiro '='
	i := strings.Index(block, "=")
	if i < 0 {
		return false
	}
	// Volta até o início do token-chave do primeiro par
	j := i - 1
	for j >= 0 && block[j] != ' ' && block[j] != '\t' && block[j] != '\n' {
		j--
	}
	header := block[:j+1]
	for _, tok := range strings.Fields(header) {
		if len(tok) == 1 && tok[0] == flag {
			return true
		}
	}
	return false
}

// buildEdgesFromArp percorre `/ip arp print detail` e cria um edge por
// entry com MAC válido. ARP não tem sysName — usamos o IP como
// remote_sys_name pra ter alguma string identificável; chassis_id = MAC.
//
// Confidence: 70 (LLDP é mais rico/confiável; ARP só prova "esse MAC
// respondeu nesta porta").
//
// Enriquecimento: se o operador colocou comentário no `/ip address` da
// interface por onde o MAC respondeu, suffixamos `local_iface` com o
// comment ("ether1 (Uplink-CGNAT)") pra contexto direto na visualização
// do grafo. O comentário cru também vai pro `raw` debaixo de
// `_local_iface_comment` pra consumo programático futuro.
func buildEdgesFromArp(output string, inv localInventory, localHostId string) []map[string]any {
	out := []map[string]any{}
	for _, blk := range splitNeighborBlocks(output) {
		f := parseKeyValueFields(blk)
		mac := strings.ToLower(strings.TrimSpace(f["mac-address"]))
		ip := strings.TrimSpace(f["address"])
		iface := strings.TrimSpace(f["interface"])
		if mac == "" || iface == "" {
			continue
		}
		// Skip explicit invalid/incomplete entries
		if strings.EqualFold(f["invalid"], "true") || strings.EqualFold(f["invalid"], "yes") {
			continue
		}
		ifaceLabel, ifaceComment := enrichIfaceWithComment(iface, inv)
		raw := copyMapToAny(f)
		if ifaceComment != "" {
			raw["_local_iface_comment"] = ifaceComment
		}
		out = append(out, map[string]any{
			"local_host_id":              localHostId,
			"local_iface":                ifaceLabel,
			"local_iface_speed_mbps":     0,
			"remote_chassis_id_subtype":  4, // MAC
			"remote_chassis_id":          mac,
			"remote_port_id_subtype":     5, // network address
			"remote_port_id":             ip,
			"remote_port_desc":           "",
			"remote_sys_name":            ip, // fallback até resolver via reverse DNS
			"remote_sys_descr":           "ARP-discovered",
			"layer":                      "L2",
			"source_protocol":            "arp",
			"link_type":                  "ethernet",
			"raw":                        raw,
		})
	}
	return out
}

// buildEdgesFromRoutes captura next-hops L3. Só rotas dynamic+active, e só
// quando o gateway é um IP (não interface). Cada gateway IP único vira um
// vizinho L3.
//
// Confidence: 60 (next-hop pode ser load-balanced ou ECMP — temos certeza
// que existe, mas a interface exata pode mudar).
//
// Enriquecimento: quando o gateway-status do RouterOS expõe a interface
// reachable (ex: "172.30.1.1 reachable via ether8"), usamos pra correlacionar
// com o comment do /ip address. Quando não, usamos a network do gateway.
func buildEdgesFromRoutes(output string, inv localInventory, localHostId string) []map[string]any {
	seen := map[string]bool{}
	out := []map[string]any{}
	for _, blk := range splitNeighborBlocks(output) {
		f := parseKeyValueFields(blk)
		gateway := strings.TrimSpace(f["gateway"])
		if gateway == "" {
			continue
		}
		// gateway pode ser "192.168.1.1" ou "192.168.1.1%ether1" — extrai IP
		gwIp := gateway
		gwIface := ""
		if idx := strings.Index(gateway, "%"); idx > 0 {
			gwIp = gateway[:idx]
			gwIface = gateway[idx+1:]
		}
		// Skip se gateway é nome de interface (rotas connected)
		if net.ParseIP(gwIp) == nil {
			continue
		}
		if seen[gwIp] {
			continue
		}
		seen[gwIp] = true

		// Se RouterOS não nos deu a iface no gateway, tenta inferir do
		// gateway-status (formato: "<gw-ip> reachable via <iface>") OU
		// achando qual /ip address é da mesma sub-rede do gw.
		if gwIface == "" {
			gwIface = parseIfaceFromGatewayStatus(f["gateway-status"])
		}
		if gwIface == "" {
			gwIface = ifaceForRemoteIp(gwIp, inv)
		}

		ifaceLabel, ifaceComment := enrichIfaceWithComment(gwIface, inv)
		raw := copyMapToAny(f)
		if ifaceComment != "" {
			raw["_local_iface_comment"] = ifaceComment
		}
		out = append(out, map[string]any{
			"local_host_id":              localHostId,
			"local_iface":                ifaceLabel,
			"local_iface_speed_mbps":     0,
			"remote_chassis_id_subtype":  5, // network address
			"remote_chassis_id":          gwIp,
			"remote_port_id_subtype":     0,
			"remote_port_id":             "",
			"remote_port_desc":           "",
			"remote_sys_name":            gwIp,
			"remote_sys_descr":           fmt.Sprintf("Route next-hop dst=%s distance=%s", f["dst-address"], f["distance"]),
			"layer":                      "L3",
			"source_protocol":            "route",
			"link_type":                  "",
			"raw":                        raw,
		})
	}
	return out
}

// parseIfaceFromGatewayStatus extrai o nome da interface de um valor de
// gateway-status no estilo "172.30.1.1 reachable via ether8" ou
// "172.30.1.1 reachable". Retorna "" quando não há dica de interface.
func parseIfaceFromGatewayStatus(status string) string {
	s := strings.TrimSpace(status)
	if s == "" {
		return ""
	}
	idx := strings.Index(s, " via ")
	if idx < 0 {
		return ""
	}
	tail := strings.TrimSpace(s[idx+len(" via "):])
	// Pode haver mais texto depois ("via ether8 distance=1") — só o primeiro token.
	if sp := strings.IndexAny(tail, " \t"); sp > 0 {
		tail = tail[:sp]
	}
	return tail
}

// ifaceForRemoteIp acha qual interface local "tem" a sub-rede de remoteIp
// inspecionando os endereços IP locais. Retorna "" quando não dá pra
// determinar (sub-rede não cobre, IP inválido, etc).
func ifaceForRemoteIp(remoteIp string, inv localInventory) string {
	target := net.ParseIP(strings.TrimSpace(remoteIp))
	if target == nil {
		return ""
	}
	for _, a := range inv.addresses {
		// a.address é "192.168.1.5/24" — ParseCIDR aceita esse formato.
		_, ipnet, err := net.ParseCIDR(a.address)
		if err != nil {
			continue
		}
		if ipnet.Contains(target) {
			return a.interfaceName
		}
	}
	return ""
}

// enrichIfaceWithComment adiciona o comentário do operador (do /ip address)
// como suffix legível no nome da interface — produz strings tipo
// "ether8 (Uplink-CGNAT)" pra que a UI mostre o papel do link sem precisar
// de uma coluna extra. Retorna também o comment cru pra duplicar no `raw`.
//
// Quando a interface não tem endereço IP associado (raro, mas acontece em
// bridges sem IP), retorna o nome cru sem suffix.
func enrichIfaceWithComment(iface string, inv localInventory) (label, comment string) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return "", ""
	}
	for _, a := range inv.addresses {
		if a.comment == "" {
			continue
		}
		if a.interfaceName == iface || a.actualInterface == iface {
			return fmt.Sprintf("%s (%s)", iface, a.comment), a.comment
		}
	}
	return iface, ""
}

// buildEdgesFromBgpPeers cria edge L3 por peer BGP estabelecido. Só peers
// no estado "established" entram (peer down não é vizinhança útil pro grafo).
//
// Confidence: 85 (BGP estabelecido é prova forte de vizinhança L3 + AS).
func buildEdgesFromBgpPeers(output string, localHostId string) []map[string]any {
	out := []map[string]any{}
	for _, blk := range splitNeighborBlocks(output) {
		f := parseKeyValueFields(blk)
		peerIp := pickFirstNonEmpty(f["remote-address"], f["address"])
		if peerIp == "" {
			continue
		}
		state := strings.ToLower(f["state"])
		if state != "" && state != "established" {
			continue
		}
		remoteAs := f["remote-as"]
		out = append(out, map[string]any{
			"local_host_id":              localHostId,
			"local_iface":                "",
			"local_iface_speed_mbps":     0,
			"remote_chassis_id_subtype":  5, // network address
			"remote_chassis_id":          peerIp,
			"remote_port_id_subtype":     0,
			"remote_port_id":             "",
			"remote_port_desc":           "",
			"remote_sys_name":            peerIp,
			"remote_sys_descr":           fmt.Sprintf("BGP peer AS=%s name=%s", remoteAs, f["name"]),
			"layer":                      "L3",
			"source_protocol":            "bgp",
			"link_type":                  "",
			"raw":                        copyMapToAny(f),
		})
	}
	return out
}

// filterSelfLoopsAdvanced descarta entries onde:
//   1. remote_sys_name bate com local identity (case-insensitive); OU
//   2. remote_chassis_id é MAC e bate com algum MAC local
//
// (#2 é o catch-all que pega self-loop mesmo quando LLDP anuncia identity
// vazio mas o MAC é claramente do próprio equipamento.)
func filterSelfLoopsAdvanced(edges []map[string]any, inv localInventory) []map[string]any {
	idLower := strings.ToLower(strings.TrimSpace(inv.identity))
	kept := make([]map[string]any, 0, len(edges))
	for _, e := range edges {
		sysName, _ := e["remote_sys_name"].(string)
		if idLower != "" && strings.ToLower(strings.TrimSpace(sysName)) == idLower {
			continue
		}
		chassisId, _ := e["remote_chassis_id"].(string)
		if mac := strings.ToLower(strings.TrimSpace(chassisId)); mac != "" && inv.macs[mac] {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}

// dedupByRemoteMac agrupa edges com mesmo (remote_chassis_id, local_iface)
// e mantém o de maior confidence. LLDP > BGP > ARP > route.
func dedupByRemoteMac(edges []map[string]any) []map[string]any {
	rank := map[string]int{
		"lldp": 95, "cdp": 95, "mndp": 90,
		"bgp": 85, "ospf": 85,
		"arp": 70, "route": 60,
		"manual": 100,
	}
	type key struct{ chassis, iface string }
	best := map[key]map[string]any{}
	bestRank := map[key]int{}
	for _, e := range edges {
		chassis, _ := e["remote_chassis_id"].(string)
		iface, _ := e["local_iface"].(string)
		if chassis == "" {
			continue // sem chassis não dá pra dedup — passa direto
		}
		k := key{chassis: strings.ToLower(chassis), iface: iface}
		proto, _ := e["source_protocol"].(string)
		r := rank[strings.ToLower(proto)]
		if existing, ok := bestRank[k]; ok && r <= existing {
			continue
		}
		best[k] = e
		bestRank[k] = r
	}
	// Preserva ordem-estável das primeiras aparições + adiciona edges sem chassis
	out := make([]map[string]any, 0, len(edges))
	added := map[key]bool{}
	for _, e := range edges {
		chassis, _ := e["remote_chassis_id"].(string)
		iface, _ := e["local_iface"].(string)
		if chassis == "" {
			out = append(out, e)
			continue
		}
		k := key{chassis: strings.ToLower(chassis), iface: iface}
		if added[k] {
			continue
		}
		if winner, ok := best[k]; ok {
			out = append(out, winner)
			added[k] = true
		}
	}
	return out
}

// runCommand é um helper pra exec one-shot via SSH numa nova session por
// comando (RouterOS não suporta múltiplos comandos numa session só).
func runCommand(ctx context.Context, client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	var stdout, stderr cappedBuffer
	stdout.cap = sshOutputCapBytes
	stderr.cap = sshOutputCapBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- session.Run(cmd) }()

	select {
	case <-runCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", runCtx.Err()
	case err = <-runErrCh:
		if err != nil {
			return stdout.String(), err
		}
	}
	return stdout.String(), nil
}

// parseSystemIdentity extrai o "name" do output de `/system identity print`.
// Formato típico:
//
//	  name: Borda-Centralnet
//
// Pode aparecer também "name=Borda-Centralnet" (sem espaços) — aceitamos
// ambos. Retorna string vazia se não encontrou.
func parseSystemIdentity(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Formato "name: value"
		if idx := strings.Index(line, "name:"); idx >= 0 {
			return strings.Trim(strings.TrimSpace(line[idx+5:]), `"`)
		}
		// Formato "name=value"
		if idx := strings.Index(line, "name="); idx >= 0 {
			val := line[idx+5:]
			// Remove aspas e espaços trailing
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"`)
			// Trunca em separadores caso a linha tenha mais campos
			for _, sep := range []string{" ", "\t"} {
				if i := strings.Index(val, sep); i >= 0 {
					val = val[:i]
				}
			}
			return val
		}
	}
	return ""
}

// filterSelfLoops descarta entries cujo remote_sys_name (LLDP identity)
// bate com o identity local do equipamento. Esse caso é típico em
// concentradores Mikrotik com bondings/VLANs onde o LLDP do próprio
// equipamento volta como vizinho em outras interfaces dele mesmo.
//
// Comparação case-insensitive porque RouterOS preserva caixa mas usuário
// edita às vezes diferente.
//
// Retorna (edges_kept, count_dropped). Quando localIdentity vazio,
// passa tudo (não temos critério).
func filterSelfLoops(edges []map[string]any, localIdentity string) ([]map[string]any, int) {
	if localIdentity == "" {
		return edges, 0
	}
	lower := strings.ToLower(localIdentity)
	kept := make([]map[string]any, 0, len(edges))
	dropped := 0
	for _, e := range edges {
		sysName, _ := e["remote_sys_name"].(string)
		if strings.ToLower(strings.TrimSpace(sysName)) == lower {
			dropped++
			continue
		}
		kept = append(kept, e)
	}
	return kept, dropped
}

// parseMikrotikNeighborDetail consome o output de `/ip neighbor print detail
// without-paging` e devolve TopologyEdgeReport-shaped entries (formato JSON
// que o scheduler converte em proto antes de mandar via ReportTopology).
//
// Formato típico:
//
//	 0   interface=ether1 address=192.168.88.1 mac-address=AA:BB:CC:DD:EE:FF
//	     identity="switch-borda" platform="MikroTik" version="6.45.7"
//	     board="CRS112-8G-4S" software-id="ABCD-1234" age=12s
//	     uptime=1d2h3m discovered-by=mndp,lldp
//
//	 1   interface=ether2 ...
//
// Entradas são separadas por linha que começa com índice numérico. Campos
// vêm em pares key=value ou key="quoted value" e podem se espalhar em
// múltiplas linhas sob o mesmo índice.
func parseMikrotikNeighborDetail(output, localHostId string) []map[string]any {
	out := []map[string]any{}
	if strings.TrimSpace(output) == "" {
		return out
	}

	// Quebra em "blocos" — cada bloco começa com uma linha que tem índice
	// numérico no começo (ex.: " 0   interface=...").
	blocks := splitNeighborBlocks(output)
	for _, blk := range blocks {
		fields := parseKeyValueFields(blk)
		if len(fields) == 0 {
			continue
		}
		edge := buildEdgeFromMikrotikFields(localHostId, fields)
		if edge != nil {
			out = append(out, edge)
		}
	}
	return out
}

func splitNeighborBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	var cur strings.Builder
	for _, ln := range lines {
		trimmed := strings.TrimLeft(ln, " \t")
		if isNeighborIndexLine(trimmed) && cur.Len() > 0 {
			blocks = append(blocks, cur.String())
			cur.Reset()
		}
		cur.WriteString(ln)
		cur.WriteByte('\n')
	}
	if cur.Len() > 0 {
		blocks = append(blocks, cur.String())
	}
	return blocks
}

// isNeighborIndexLine detecta linhas como "0  interface=..." — índice
// numérico seguido de ao menos um espaço.
func isNeighborIndexLine(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && i < len(s) && (s[i] == ' ' || s[i] == '\t')
}

// parseKeyValueFields extrai pares key=value e key="quoted value" do bloco.
// RouterOS usa quote pra valores com espaço; valores numéricos/sem espaço
// vêm sem quote.
func parseKeyValueFields(block string) map[string]string {
	out := map[string]string{}
	// Remove o prefixo do índice e flags da primeira linha pra simplificar.
	// Ex.: "   0   interface=ether1 ..." → "interface=ether1 ..."
	cleaned := stripLeadingIndex(block)
	// Depois disso, o bloco é só pares key=value separados por whitespace,
	// possivelmente quebrados em múltiplas linhas.
	i := 0
	n := len(cleaned)
	for i < n {
		// Pula whitespace
		for i < n && (cleaned[i] == ' ' || cleaned[i] == '\t' || cleaned[i] == '\n' || cleaned[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}
		// Lê key até '='
		keyStart := i
		for i < n && cleaned[i] != '=' && cleaned[i] != ' ' && cleaned[i] != '\t' && cleaned[i] != '\n' {
			i++
		}
		if i >= n || cleaned[i] != '=' {
			// Token sem '=' → ignora
			continue
		}
		key := strings.ToLower(cleaned[keyStart:i])
		i++ // consome '='
		// Lê value
		var val string
		if i < n && cleaned[i] == '"' {
			i++ // consome aspa abertura
			valStart := i
			for i < n && cleaned[i] != '"' {
				i++
			}
			val = cleaned[valStart:i]
			if i < n {
				i++ // consome aspa fechamento
			}
		} else {
			valStart := i
			for i < n && cleaned[i] != ' ' && cleaned[i] != '\t' && cleaned[i] != '\n' && cleaned[i] != '\r' {
				i++
			}
			val = cleaned[valStart:i]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func stripLeadingIndex(block string) string {
	// Procura primeiro '=' do bloco. O texto antes do primeiro espaço-key
	// que precede esse '=' é o "header" (índice + flags). Mais simples:
	// avança até encontrar uma sequência letra+'=' (key= padrão).
	for i := 0; i < len(block); i++ {
		c := block[i]
		if c == '=' {
			// Volta até o início do token chave
			j := i - 1
			for j >= 0 && block[j] != ' ' && block[j] != '\t' && block[j] != '\n' {
				j--
			}
			return block[j+1:]
		}
	}
	return block
}

// buildEdgeFromMikrotikFields converte os campos parseados em um
// TopologyEdgeReport JSON-shaped. Mapping:
//
//	interface       → local_iface
//	mac-address     → remote_chassis_id (subtype 4 = MAC)
//	address / address4 / address6 → fallback chassis_id se MAC ausente
//	identity        → remote_sys_name
//	platform/board/version → remote_sys_descr (concatenado pra contexto)
//	interface (do remoto, se vier em "interface-name") → remote_port_id
//
// discovered-by mostra qual protocolo (mndp/lldp/cdp) achou o vizinho.
// Reportamos como source_protocol={lldp,cdp,mndp} usando a string do RouterOS.
func buildEdgeFromMikrotikFields(localHostId string, f map[string]string) map[string]any {
	if len(f) == 0 {
		return nil
	}
	mac := f["mac-address"]
	addr := pickFirstNonEmpty(f["address"], f["address4"], f["address6"])
	identity := f["identity"]
	platform := f["platform"]
	board := f["board"]
	version := f["version"]
	iface := f["interface"]
	discoveredBy := f["discovered-by"]

	if mac == "" && addr == "" && identity == "" {
		// Sem nenhuma identificação útil — descarta
		return nil
	}

	chassisId := mac
	chassisSubtype := 4 // MAC
	if chassisId == "" {
		chassisId = addr
		chassisSubtype = 5 // network address
	}

	descrParts := []string{}
	if platform != "" {
		descrParts = append(descrParts, platform)
	}
	if board != "" {
		descrParts = append(descrParts, board)
	}
	if version != "" {
		descrParts = append(descrParts, "v"+version)
	}
	descr := strings.Join(descrParts, " ")

	proto := selectProtocol(discoveredBy)

	edge := map[string]any{
		"local_host_id":              localHostId,
		"local_iface":                iface,
		"local_iface_speed_mbps":     0,
		"remote_chassis_id_subtype":  chassisSubtype,
		"remote_chassis_id":          strings.ToLower(chassisId),
		"remote_port_id_subtype":     0,
		"remote_port_id":             "",
		"remote_port_desc":           "",
		"remote_sys_name":            identity,
		"remote_sys_descr":           descr,
		"layer":                      "L2",
		"source_protocol":            proto,
		"link_type":                  "ethernet",
		"raw":                        copyMapToAny(f),
	}
	return edge
}

// selectProtocol prioriza LLDP > CDP > MNDP quando o RouterOS lista vários
// (formato típico: "discovered-by=mndp,lldp"). LLDP é o padrão de mercado;
// MNDP só vira fonte quando é o único disponível (rede 100% Mikrotik).
func selectProtocol(discoveredBy string) string {
	val := strings.ToLower(strings.TrimSpace(discoveredBy))
	if val == "" {
		return "lldp"
	}
	if strings.Contains(val, "lldp") {
		return "lldp"
	}
	if strings.Contains(val, "cdp") {
		return "cdp"
	}
	if strings.Contains(val, "mndp") {
		return "mndp"
	}
	return "lldp"
}

func pickFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func copyMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
