package snmp

import "testing"

// Normalização IF-MIB: perfis importados batizam as colunas como
// community.<vendor>.net_if_* — o backend Telvyn só lê snmp.if.*. canonMetricName
// mapeia pelo OID (não pelo texto), cobrindo os ~169 perfis importados.
func TestCanonMetricName_IfMib(t *testing.T) {
	cases := []struct {
		oid, in, want string
	}{
		// octets: 32-bit e 64-bit (HC) → mesmo canônico
		{"1.3.6.1.2.1.2.2.1.10", "community.mikrotik_x.net_if_in", "snmp.if.in_octets"},
		{"1.3.6.1.2.1.31.1.1.1.6", "community.mikrotik_aa_snmp_mikrotik_ccr_1036.net_if_in", "snmp.if.in_octets"},
		{"1.3.6.1.2.1.31.1.1.1.10", "community.x.net_if_out", "snmp.if.out_octets"},
		{"1.3.6.1.2.1.2.2.1.8", "community.x.net_if_status", "snmp.if.oper_status"},
		{"1.3.6.1.2.1.2.2.1.14", "community.x.net_if_in_errors", "snmp.if.in_errors"},
		{"1.3.6.1.2.1.2.2.1.13", "community.x.net_if_in_discards", "snmp.if.in_discards"},
		{"1.3.6.1.2.1.31.1.1.1.15", "community.x.net_if_speed", "snmp.if.high_speed"},
		// aceita OID com leading dot
		{".1.3.6.1.2.1.2.2.1.16", "community.x.net_if_out", "snmp.if.out_octets"},
		// perfil bundled já canônico → no-op
		{"1.3.6.1.2.1.2.2.1.10", "snmp.if.in_octets", "snmp.if.in_octets"},
		// OID desconhecido → mantém o nome do perfil
		{"1.3.6.1.4.1.14988.1.1.3.1.0", "mikrotik.cpu.load", "mikrotik.cpu.load"},
	}
	for _, c := range cases {
		if got := canonMetricName(c.oid, c.in); got != c.want {
			t.Errorf("canonMetricName(%q, %q) = %q; want %q", c.oid, c.in, got, c.want)
		}
	}
}
