package snmp

import (
	"strings"
	"testing"
)

func TestLoadProfile_AllParseable(t *testing.T) {
	all, err := AllProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("AllProfiles retornou vazio")
	}

	for _, profile := range all {
		name := profile.Name
		t.Run(name, func(t *testing.T) {
			p, err := LoadProfile(name)
			if err != nil {
				t.Fatalf("LoadProfile(%q): %v", name, err)
			}
			if p == nil {
				t.Fatalf("LoadProfile(%q): nil profile", name)
			}
			if p.Name != name {
				t.Fatalf("LoadProfile(%q): Name=%q want %q", name, p.Name, name)
			}
			if len(p.SysObjectID) == 0 {
				t.Fatalf("LoadProfile(%q): sysobjectid vazio", name)
			}
			if len(p.Metrics) == 0 {
				t.Fatalf("LoadProfile(%q): sem metrics", name)
			}
		})
	}
}

func TestLoadProfile_LinuxNetSnmp_Coverage(t *testing.T) {
	p, err := LoadProfile("linux-net-snmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Metrics) < 5 {
		t.Fatalf("linux-net-snmp metrics=%d want >=5 (load+mem+cpu+ifTable)", len(p.Metrics))
	}
}

func TestAllProfiles_ReturnsBundledCatalog(t *testing.T) {
	all, err := AllProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 7 {
		t.Fatalf("AllProfiles len=%d want at least 7", len(all))
	}
}

func TestLoadProfile_Unknown(t *testing.T) {
	_, err := LoadProfile("nope-vendor")
	if err == nil {
		t.Fatal("LoadProfile(nope-vendor) deveria falhar")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown profile") {
		t.Fatalf("erro=%q nao contem 'unknown profile'", msg)
	}
	// Mensagem deve listar pelo menos linux-net-snmp como hint.
	if !strings.Contains(msg, "linux-net-snmp") {
		t.Fatalf("erro=%q nao lista perfis validos", msg)
	}
}

func TestMatchSysObjectID_Table(t *testing.T) {
	all, err := AllProfiles()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		sysOid     string
		expectName string
		expectOK   bool
		descricao  string
	}{
		{"1.3.6.1.4.1.8072.3.2.10", "linux-net-snmp", true, "exact match Linux net-snmp"},
		{"1.3.6.1.4.1.9.1.617", "cisco-ios", true, "Cisco Catalyst 3850 (prefix 1.3.6.1.4.1.9.1.*)"},
		{"1.3.6.1.4.1.9.12.3.1.3.1234", "cisco-nx-os", true, "Cisco Nexus — NX-OS prefix mais especifico vence sobre IOS"},
		{"1.3.6.1.4.1.2636.1.1.1.99", "juniper-junos", true, "Juniper MX"},
		{"1.3.6.1.4.1.14988.1", "mikrotik-routeros", true, "Mikrotik exact"},
		{"1.3.6.1.4.1.14988.1.2.3", "mikrotik-routeros", true, "Mikrotik subtree"},
		{".1.3.6.1.4.1.14988.1", "mikrotik-routeros", true, "leading dot tolerado"},
		{"1.3.6.1.4.1.99999.1", "", false, "vendor desconhecido — nao casa"},
		{"", "", false, "string vazia"},
	}

	for _, c := range cases {
		t.Run(c.descricao, func(t *testing.T) {
			got, ok := MatchSysObjectID(all, c.sysOid)
			if ok != c.expectOK {
				t.Fatalf("MatchSysObjectID(%q) ok=%v want %v", c.sysOid, ok, c.expectOK)
			}
			if !ok {
				return
			}
			if got.Name != c.expectName {
				t.Fatalf("MatchSysObjectID(%q) name=%q want %q", c.sysOid, got.Name, c.expectName)
			}
		})
	}
}

func TestMatchSysObjectID_SkipsManualOnlyProfiles(t *testing.T) {
	all, err := AllProfiles()
	if err != nil {
		t.Fatal(err)
	}

	ccr, err := LoadProfile("mikrotik-ccr1036")
	if err != nil {
		t.Fatal(err)
	}
	if ccr.autoDetectEnabled() {
		t.Fatal("mikrotik-ccr1036 deve ser manual-only para nao capturar todo RouterOS")
	}

	got, ok := MatchSysObjectID(all, "1.3.6.1.4.1.14988.1")
	if !ok {
		t.Fatal("MatchSysObjectID deveria encontrar fallback RouterOS")
	}
	if got.Name != "mikrotik-routeros" {
		t.Fatalf("MatchSysObjectID escolheu %q, want mikrotik-routeros", got.Name)
	}
}

// Teste CHECK-05 reinterpretado: perfil mikrotik deve carregar OIDs da
// MIKROTIK-MIB (.1.3.6.1.4.1.14988.*). Sem isso o plan nao fechou a
// reinterpretacao do requirement.
func TestMikrotikProfile_ContainsMikrotikMIB(t *testing.T) {
	p, err := LoadProfile("mikrotik-routeros")
	if err != nil {
		t.Fatal(err)
	}
	const mikrotikPrefix = "1.3.6.1.4.1.14988."
	found := false
	for _, m := range p.Metrics {
		if m.Symbol != nil && strings.HasPrefix(m.Symbol.OID, mikrotikPrefix) {
			found = true
			break
		}
		if m.Table != nil && strings.HasPrefix(m.Table.OID, mikrotikPrefix) {
			found = true
			break
		}
		for _, s := range m.Symbols {
			if strings.HasPrefix(s.OID, mikrotikPrefix) {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("perfil mikrotik-routeros nao referencia OIDs MIKROTIK-MIB (.1.3.6.1.4.1.14988.*)")
	}
}

func TestProfileTags_StaticTagsParseable(t *testing.T) {
	p, err := LoadProfile("linux-net-snmp")
	if err != nil {
		t.Fatal(err)
	}
	foundVendor := false
	for _, t := range p.MetricTags {
		if t.Tag == "vendor" && t.Value == "linux-net-snmp" {
			foundVendor = true
		}
	}
	if !foundVendor {
		t.Fatal("perfil linux-net-snmp deve ter tag estatica vendor=linux-net-snmp")
	}
}
