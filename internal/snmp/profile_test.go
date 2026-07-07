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
			// Todo perfil precisa ser util: OU casa por sysObjectID OU coleta
			// metrica. Profiles do Datadog trazem duas categorias legitimas que
			// nao tem os dois: "manual-only" (metrica, sem sysObjectID — operador
			// escolhe pelo nome, ex. brocade/a10) e "so-identificacao"
			// (sysObjectID, sem metrica — ex. tripplite/zebra-printer, fiel ao DD).
			if len(p.SysObjectID) == 0 && len(p.Metrics) == 0 {
				t.Fatalf("LoadProfile(%q): sem sysobjectid E sem metrics (perfil inutil)", name)
			}
			// Metricas presentes tem que ser bem formadas (symbol OU table).
			for _, m := range p.Metrics {
				if m.Symbol == nil && m.Table == nil {
					t.Fatalf("LoadProfile(%q): metric sem symbol nem table", name)
				}
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
		{"1.3.6.1.4.1.9.1.617", "cisco-catalyst", true, "Catalyst 3560G48TS — perfil Datadog especifico vence o cisco-ios generico"},
		{"1.3.6.1.4.1.9.1.99999999", "cisco-ios", true, "IOS nao listado pelo Datadog cai no nosso cisco-ios (prefix 9.1.*)"},
		{"1.3.6.1.4.1.9.12.3.1.3.1234", "cisco-nx-os", true, "Cisco Nexus — NX-OS prefix mais especifico vence sobre IOS"},
		{"1.3.6.1.4.1.2636.1.1.1.99", "juniper-junos", true, "Juniper MX"},
		{"1.3.6.1.4.1.14988.1", "mikrotik-router", true, "Mikrotik exact (perfil do Datadog)"},
		{"1.3.6.1.4.1.14988.1.2.3", "mikrotik-router", true, "Mikrotik subtree"},
		{".1.3.6.1.4.1.14988.1", "mikrotik-router", true, "leading dot tolerado"},
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

	// generic-device (Datadog) casa 1.3.6.1.4.* (árvore enterprises inteira) mas é
	// manual-only (auto_detect:false) — nunca deve ser sugerido pelo auto-match;
	// o fallback de device desconhecido fica a cargo do generic-snmpv2 (via código).
	gd, err := LoadProfile("generic-device")
	if err != nil {
		t.Fatal(err)
	}
	if gd.autoDetectEnabled() {
		t.Fatal("generic-device deve ser manual-only (auto_detect:false) pra nao roubar o auto-match")
	}

	// Um enterprise OID que nenhum perfil específico cobre NÃO deve casar — se
	// generic-device auto-matchasse, ele engoliria qualquer device desconhecido.
	if got, ok := MatchSysObjectID(all, "1.3.6.1.4.1.99999.7"); ok {
		t.Fatalf("MatchSysObjectID casou %q num OID desconhecido — generic-device nao devia auto-matchar", got.Name)
	}
}

// Perfil mikrotik (mikrotik-router, adotado do Datadog) deve carregar OIDs da
// MIKROTIK-MIB (.1.3.6.1.4.1.14988.*) — incl. temperatura em .3.6/.3.10.
func TestMikrotikProfile_ContainsMikrotikMIB(t *testing.T) {
	p, err := LoadProfile("mikrotik-router")
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

// Catalogo Datadog importado (Fase 2 da adocao NDM): o conversor traz a
// biblioteca oficial BSD-3 alem dos nossos hand-curated. Guarda contra
// regressao que esvazie o import ou quebre as categorias novas.
func TestCatalog_DatadogLibraryImported(t *testing.T) {
	all, err := AllProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 150 {
		t.Fatalf("catalogo tem %d perfis, esperado >=150 (biblioteca Datadog + hand-curated)", len(all))
	}
	// Perfis Datadog representativos existem e carregam.
	for _, name := range []string{"cisco-catalyst", "fortinet-fortigate", "apc_ups", "aruba-switch"} {
		if _, err := LoadProfile(name); err != nil {
			t.Fatalf("perfil Datadog %q ausente/ilegivel: %v", name, err)
		}
	}
	// Manual-only: tem metrica de interface mas nenhum sysObjectID (nunca auto-matcha).
	man, err := LoadProfile("brocade")
	if err != nil {
		t.Fatalf("manual-only brocade ausente: %v", err)
	}
	if len(man.SysObjectID) != 0 {
		t.Fatalf("brocade deveria ser manual-only (sem sysObjectID), tem %d", len(man.SysObjectID))
	}
	if len(man.Metrics) == 0 {
		t.Fatal("brocade manual-only deveria ter metricas de interface")
	}
	// Nenhum resquicio dos community-templates (nomenclatura community.*).
	for _, p := range all {
		for _, m := range p.Metrics {
			if m.Symbol != nil && strings.HasPrefix(m.Symbol.Name, "community.") {
				t.Fatalf("perfil %q ainda emite metrica community.* (lixo Zabbix): %s", p.Name, m.Symbol.Name)
			}
			for _, s := range m.Symbols {
				if strings.HasPrefix(s.Name, "community.") {
					t.Fatalf("perfil %q ainda emite metrica community.* (lixo Zabbix): %s", p.Name, s.Name)
				}
			}
		}
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
