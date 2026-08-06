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

// Normalização CPU/memória/uptime: os perfis importados usam OIDs padrão
// (HOST-RESOURCES/UCD/SNMPv2) mas batizam como hrProcessorLoad/cpu.usage/memory.free.
// O DeviceMetricsTab e o MonitorDrawer leem snmp.hr.processor_load / snmp.hr.storage_used
// / snmp.mem.avail_kb / snmp.sys.uptime — normalizar por OID faz acender em todo fabricante.
func TestCanonMetricName_CpuMemUptime(t *testing.T) {
	cases := []struct {
		oid, in, want string
	}{
		// CPU (HOST-RESOURCES hrProcessorLoad) — catálogos usam cpu.usage/hrProcessorLoad
		{"1.3.6.1.2.1.25.3.3.1.2", "cpu.usage", "snmp.hr.processor_load"},
		{"1.3.6.1.2.1.25.3.3.1.2", "hrProcessorLoad", "snmp.hr.processor_load"},
		// Armazenamento (HOST-RESOURCES hrStorage)
		{"1.3.6.1.2.1.25.2.3.1.5", "hrStorageSize", "snmp.hr.storage_size"},
		{"1.3.6.1.2.1.25.2.3.1.6", "memory.used", "snmp.hr.storage_used"},
		// Memória real (UCD)
		{"1.3.6.1.4.1.2021.4.5.0", "memory.total", "snmp.mem.total_kb"},
		{"1.3.6.1.4.1.2021.4.6.0", "memory.free", "snmp.mem.avail_kb"},
		// Uptime (SNMPv2 sysUpTime), tolera leading dot
		{"1.3.6.1.2.1.1.3.0", "sysUpTimeInstance", "snmp.sys.uptime"},
		{".1.3.6.1.2.1.1.3.0", "uptime", "snmp.sys.uptime"},
		// Temperatura MikroTik (o perfil usa nome da MIB; canonizamos
		// pra mikrotik.health.temp_* pra cair no widget de Temperatura). O OID é o do
		// PERFIL (sem .0) — getScalar tenta .0 na coleta, mas canonMetricName usa o do perfil.
		{"1.3.6.1.4.1.14988.1.1.3.6", "mtxrHlCpuTemperature", "mikrotik.health.temp_cpu"},
		{"1.3.6.1.4.1.14988.1.1.3.10", "mtxrHlTemperature", "mikrotik.health.temp_system"},
		// no-op pros hand-curated que já emitem o canônico no mesmo OID
		{"1.3.6.1.2.1.25.3.3.1.2", "snmp.hr.processor_load", "snmp.hr.processor_load"},
		// OID de CPU vendor-específico (MIKROTIK-MIB) NÃO é normalizado — mantém o nome
		{"1.3.6.1.4.1.14988.1.1.3.1.0", "mikrotik.cpu.load", "mikrotik.cpu.load"},
	}
	for _, c := range cases {
		if got := canonMetricName(c.oid, c.in); got != c.want {
			t.Errorf("canonMetricName(%q, %q) = %q; want %q", c.oid, c.in, got, c.want)
		}
	}
}
