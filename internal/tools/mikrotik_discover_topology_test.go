package tools

import "testing"

const sampleNeighborOutput = ` 0   interface=ether1 address=192.168.88.10 address4=192.168.88.10 address6="" mac-address=AA:BB:CC:DD:EE:01
     identity="switch-borda-01" platform="MikroTik" version="7.10.2"
     board="CRS112-8G-4S" software-id="ABCD-1234"
     uptime=1d2h3m discovered-by=mndp,lldp

 1   interface=sfp-sfpplus1 address=10.0.0.5 mac-address=BB:CC:DD:EE:FF:02
     identity="ativos.bixnet.com.br" platform="Cisco" version="15.4(3)M3"
     board="C2960X" discovered-by=cdp

 2   interface=ether3 address=10.0.0.6 mac-address=11:22:33:44:55:66
     identity="" platform="" version="" discovered-by=lldp
`

func TestParseMikrotikNeighborDetail_BasicCount(t *testing.T) {
	edges := parseMikrotikNeighborDetail(sampleNeighborOutput, "CCR1036")
	if len(edges) != 3 {
		t.Fatalf("expected 3 edges, got %d", len(edges))
	}
}

func TestParseMikrotikNeighborDetail_FieldsFirstEntry(t *testing.T) {
	edges := parseMikrotikNeighborDetail(sampleNeighborOutput, "CCR1036")
	e := edges[0]
	if e["local_host_id"] != "CCR1036" {
		t.Errorf("local_host_id: %v", e["local_host_id"])
	}
	if e["local_iface"] != "ether1" {
		t.Errorf("local_iface: %v", e["local_iface"])
	}
	if e["remote_chassis_id"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("remote_chassis_id: %v", e["remote_chassis_id"])
	}
	if e["remote_chassis_id_subtype"] != 4 {
		t.Errorf("remote_chassis_id_subtype: %v", e["remote_chassis_id_subtype"])
	}
	if e["remote_sys_name"] != "switch-borda-01" {
		t.Errorf("remote_sys_name: %v", e["remote_sys_name"])
	}
	if e["source_protocol"] != "lldp" {
		t.Errorf("source_protocol (mndp,lldp → prefer lldp): %v", e["source_protocol"])
	}
	descr, _ := e["remote_sys_descr"].(string)
	if descr == "" || !contains(descr, "MikroTik") || !contains(descr, "CRS112") {
		t.Errorf("remote_sys_descr should mention vendor+board: %q", descr)
	}
}

func TestParseMikrotikNeighborDetail_CdpProtocol(t *testing.T) {
	edges := parseMikrotikNeighborDetail(sampleNeighborOutput, "CCR1036")
	if edges[1]["source_protocol"] != "cdp" {
		t.Errorf("entry 1 (discovered-by=cdp): got %v", edges[1]["source_protocol"])
	}
	if edges[1]["remote_sys_name"] != "ativos.bixnet.com.br" {
		t.Errorf("entry 1 sys_name: %v", edges[1]["remote_sys_name"])
	}
}

func TestParseMikrotikNeighborDetail_EmptyIdentityKept(t *testing.T) {
	// Entry 2 has identity="" but a valid MAC — should still be kept (chassis MAC suffices)
	edges := parseMikrotikNeighborDetail(sampleNeighborOutput, "CCR1036")
	if edges[2]["remote_chassis_id"] != "11:22:33:44:55:66" {
		t.Errorf("entry 2 chassis: %v", edges[2]["remote_chassis_id"])
	}
}

func TestParseMikrotikNeighborDetail_EmptyOutput(t *testing.T) {
	edges := parseMikrotikNeighborDetail("", "host")
	if len(edges) != 0 {
		t.Errorf("empty input should give 0 edges, got %d", len(edges))
	}
	edges = parseMikrotikNeighborDetail("   \n  \n", "host")
	if len(edges) != 0 {
		t.Errorf("whitespace-only input should give 0 edges, got %d", len(edges))
	}
}

func TestSelectProtocol(t *testing.T) {
	cases := map[string]string{
		"":             "lldp",
		"lldp":         "lldp",
		"mndp,lldp":    "lldp",
		"cdp,mndp":     "cdp",
		"mndp":         "mndp",
		"unknown_xyz":  "lldp",
		"   LLDP   ":   "lldp",
	}
	for in, want := range cases {
		if got := selectProtocol(in); got != want {
			t.Errorf("selectProtocol(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsNeighborIndexLine(t *testing.T) {
	yes := []string{"0  interface=x", "12 foo=bar", "9    address=1.2.3.4"}
	no := []string{"", "foo=bar", "  interface=x", "abc"}
	for _, s := range yes {
		if !isNeighborIndexLine(s) {
			t.Errorf("isNeighborIndexLine(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isNeighborIndexLine(s) {
			t.Errorf("isNeighborIndexLine(%q) = true, want false", s)
		}
	}
}

func TestParseSystemIdentity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"  name: Borda-Centralnet\n", "Borda-Centralnet"},
		{"  name: \"Borda Central\"\n", "Borda Central"},
		{"name=CCR1036\n", "CCR1036"},
		{"name=core-router something else\n", "core-router"},
		{"  comment\n", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseSystemIdentity(c.in); got != c.want {
			t.Errorf("parseSystemIdentity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFilterSelfLoops(t *testing.T) {
	edges := []map[string]any{
		{"remote_sys_name": "Borda-Centralnet"},
		{"remote_sys_name": "switch-borda-01"},
		{"remote_sys_name": "BORDA-CENTRALNET"}, // case-insensitive
		{"remote_sys_name": ""},
		{"remote_sys_name": "ativos.bixnet.com.br"},
	}
	kept, dropped := filterSelfLoops(edges, "Borda-Centralnet")
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
	if len(kept) != 3 {
		t.Errorf("kept count = %d, want 3", len(kept))
	}
	// Sem identity local → não filtra nada
	all, drop := filterSelfLoops(edges, "")
	if drop != 0 || len(all) != len(edges) {
		t.Errorf("empty identity should pass-through: dropped=%d kept=%d", drop, len(all))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

const sampleAddressDetail = ` 0   address=192.168.1.5/24 network=192.168.1.0 interface=ether1 actual-interface=ether1
 1 D address=10.10.0.1/30 network=10.10.0.0 interface=vlan100 actual-interface=ether2 comment="Uplink-CGNAT"
 2   address=172.30.1.5/24 network=172.30.1.0 interface=ether8 actual-interface=ether8 comment="PEERING-LACNIC"
 3 X address=10.99.0.1/24 network=10.99.0.0 interface=ether9 actual-interface=ether9 comment="Disabled-WIP"
`

func TestParseAddressDetail_CapturesCommentAndDisabled(t *testing.T) {
	addrs := parseAddressDetail(sampleAddressDetail)
	if len(addrs) != 3 {
		t.Fatalf("expected 3 enabled addresses, got %d", len(addrs))
	}
	// entry 0: no comment
	if addrs[0].interfaceName != "ether1" || addrs[0].comment != "" {
		t.Errorf("entry 0: %+v", addrs[0])
	}
	// entry 1: vlan100 over ether2 with comment
	if addrs[1].interfaceName != "vlan100" || addrs[1].actualInterface != "ether2" {
		t.Errorf("entry 1 iface mismatch: %+v", addrs[1])
	}
	if addrs[1].comment != "Uplink-CGNAT" {
		t.Errorf("entry 1 comment: %q", addrs[1].comment)
	}
	// entry 2: ether8 PEERING
	if addrs[2].comment != "PEERING-LACNIC" {
		t.Errorf("entry 2 comment: %q", addrs[2].comment)
	}
	// entry 3 disabled — must be dropped
	for _, a := range addrs {
		if a.comment == "Disabled-WIP" {
			t.Errorf("disabled address should be skipped")
		}
	}
}

func TestEnrichIfaceWithComment(t *testing.T) {
	inv := localInventory{
		addresses: []addressInfo{
			{address: "10.10.0.1/30", interfaceName: "vlan100", actualInterface: "ether2", comment: "Uplink-CGNAT"},
			{address: "172.30.1.5/24", interfaceName: "ether8", actualInterface: "ether8", comment: "PEERING-LACNIC"},
			{address: "192.168.1.5/24", interfaceName: "ether1", actualInterface: "ether1"}, // no comment
		},
	}
	cases := []struct {
		iface, wantLabel, wantComment string
	}{
		{"ether8", "ether8 (PEERING-LACNIC)", "PEERING-LACNIC"},
		{"vlan100", "vlan100 (Uplink-CGNAT)", "Uplink-CGNAT"},
		{"ether2", "ether2 (Uplink-CGNAT)", "Uplink-CGNAT"}, // physical iface match via actual-interface
		{"ether1", "ether1", ""},                            // no comment → no suffix
		{"ether7", "ether7", ""},                            // no address → unchanged
		{"", "", ""},
	}
	for _, c := range cases {
		gotLabel, gotComment := enrichIfaceWithComment(c.iface, inv)
		if gotLabel != c.wantLabel || gotComment != c.wantComment {
			t.Errorf("enrich(%q) = (%q,%q), want (%q,%q)", c.iface, gotLabel, gotComment, c.wantLabel, c.wantComment)
		}
	}
}

func TestParseIfaceFromGatewayStatus(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"172.30.1.1 reachable":            "",
		"172.30.1.1 reachable via ether8": "ether8",
		"10.0.0.1 reachable via vlan10 distance=1": "vlan10",
		"weird format no via":             "",
	}
	for in, want := range cases {
		if got := parseIfaceFromGatewayStatus(in); got != want {
			t.Errorf("parseIfaceFromGatewayStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIfaceForRemoteIp(t *testing.T) {
	inv := localInventory{
		addresses: []addressInfo{
			{address: "192.168.1.5/24", interfaceName: "ether1"},
			{address: "10.10.0.1/30", interfaceName: "vlan100"},
		},
	}
	cases := map[string]string{
		"192.168.1.10": "ether1",
		"10.10.0.2":    "vlan100",
		"8.8.8.8":      "", // no covering subnet
		"":             "",
		"not-an-ip":    "",
	}
	for in, want := range cases {
		if got := ifaceForRemoteIp(in, inv); got != want {
			t.Errorf("ifaceForRemoteIp(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildEdgesFromArp_EnrichesIfaceComment(t *testing.T) {
	inv := localInventory{
		addresses: []addressInfo{
			{address: "172.30.1.5/24", interfaceName: "ether8", actualInterface: "ether8", comment: "PEERING-LACNIC"},
		},
	}
	arpOut := ` 0   address=172.30.1.10 mac-address=BC:24:11:4C:FE:B9 interface=ether8 published=no
 1   address=192.168.5.3 mac-address=AA:BB:CC:DD:EE:FF interface=ether9 published=no
`
	edges := buildEdgesFromArp(arpOut, inv, "CCR1036")
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}
	// entry 0: ether8 → enriched
	if got := edges[0]["local_iface"]; got != "ether8 (PEERING-LACNIC)" {
		t.Errorf("entry 0 local_iface: %v", got)
	}
	if edges[0]["source_protocol"] != "arp" {
		t.Errorf("source_protocol must be arp, got %v", edges[0]["source_protocol"])
	}
	raw0, _ := edges[0]["raw"].(map[string]any)
	if raw0["_local_iface_comment"] != "PEERING-LACNIC" {
		t.Errorf("entry 0 raw _local_iface_comment: %v", raw0["_local_iface_comment"])
	}
	// entry 1: ether9 has no comment → unchanged
	if got := edges[1]["local_iface"]; got != "ether9" {
		t.Errorf("entry 1 local_iface: %v", got)
	}
	raw1, _ := edges[1]["raw"].(map[string]any)
	if _, ok := raw1["_local_iface_comment"]; ok {
		t.Errorf("entry 1 should NOT have _local_iface_comment in raw")
	}
}

func TestBuildEdgesFromRoutes_InfersIfaceFromGatewayStatus(t *testing.T) {
	inv := localInventory{
		addresses: []addressInfo{
			{address: "172.30.1.5/24", interfaceName: "ether8", actualInterface: "ether8", comment: "Uplink-CGNAT"},
		},
	}
	routeOut := ` 0   distance=1 dst-address=0.0.0.0/0 gateway=172.30.1.1 gateway-status="172.30.1.1 reachable via ether8" scope=30 target-scope=10
`
	edges := buildEdgesFromRoutes(routeOut, inv, "CCR1036")
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0]["source_protocol"] != "route" {
		t.Errorf("source_protocol: %v", edges[0]["source_protocol"])
	}
	if got := edges[0]["local_iface"]; got != "ether8 (Uplink-CGNAT)" {
		t.Errorf("local_iface should be enriched: got %v", got)
	}
}

func TestBuildEdgesFromRoutes_FallsBackToSubnetMatch(t *testing.T) {
	// gateway-status sem "via", mas o gateway IP cai numa sub-rede que sabemos.
	inv := localInventory{
		addresses: []addressInfo{
			{address: "172.30.1.5/24", interfaceName: "ether8", actualInterface: "ether8", comment: "Uplink-CGNAT"},
		},
	}
	routeOut := ` 0   distance=1 dst-address=0.0.0.0/0 gateway=172.30.1.1 gateway-status="172.30.1.1 reachable" scope=30
`
	edges := buildEdgesFromRoutes(routeOut, inv, "CCR1036")
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if got := edges[0]["local_iface"]; got != "ether8 (Uplink-CGNAT)" {
		t.Errorf("local_iface should fall back to subnet-match enrichment: %v", got)
	}
}

func TestBlockHasFlag(t *testing.T) {
	cases := []struct {
		blk  string
		flag byte
		want bool
	}{
		{" 0   address=1.2.3.4", 'X', false},
		{" 1 D address=1.2.3.4", 'D', true},
		{" 2 X address=1.2.3.4", 'X', true},
		{" 3 D X address=1.2.3.4", 'X', true},
		{" 3 D X address=1.2.3.4", 'I', false},
		{"address=1.2.3.4", 'X', false},
		{"", 'X', false},
	}
	for _, c := range cases {
		if got := blockHasFlag(c.blk, c.flag); got != c.want {
			t.Errorf("blockHasFlag(%q, %q) = %v, want %v", c.blk, c.flag, got, c.want)
		}
	}
}
