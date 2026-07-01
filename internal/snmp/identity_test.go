package snmp

import "testing"

func TestParseSysDescr(t *testing.T) {
	cases := []struct {
		descr, os, ver string
	}{
		{"RouterOS RB750Gr3 6.48.3 (stable)", "RouterOS", "6.48.3"},
		{"Cisco IOS Software, C2960 Software, Version 15.2(4)M", "Cisco IOS", "15.2"},
		{"Cisco NX-OS(tm) n9000, Software Version 9.3(5)", "Cisco NX-OS", "9.3"},
		{"Juniper Networks, Inc. junos 20.4R3", "Junos", "20.4"},
		{"Linux debian 5.10.0", "", ""}, // não reconhecido → vazio
		{"", "", ""},
	}
	for _, c := range cases {
		os, ver := parseSysDescr(c.descr)
		if os != c.os || ver != c.ver {
			t.Errorf("parseSysDescr(%q) = (%q,%q), quero (%q,%q)", c.descr, os, ver, c.os, c.ver)
		}
	}
}
