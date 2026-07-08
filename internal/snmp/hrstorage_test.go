package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// O enriquecimento do hrStorageTable é GENÉRICO (keyed no OID padrão da
// HOST-RESOURCES-MIB) — vale pra Mikrotik, Cisco, Fortinet, Linux e qualquer um.
// Cobre os dois bugs: (a) blocos lidos como bytes (× unidade de alocação) e
// (b) RAM vs disco decidido pelo hrStorageType (código), não pelo texto.
func TestEnrichHrStorageRow(t *testing.T) {
	// Row de RAM: type=hrStorageRam, descr="main memory", bloco=1024 bytes.
	ram := map[string]gosnmp.SnmpPDU{
		".1.3.6.1.2.1.25.2.3.1.2": {Value: ".1.3.6.1.2.1.25.2.1.2"}, // hrStorageType → RAM
		".1.3.6.1.2.1.25.2.3.1.3": {Value: "main memory"},           // hrStorageDescr
		".1.3.6.1.2.1.25.2.3.1.4": {Value: 1024},                    // hrStorageAllocationUnits
		".1.3.6.1.2.1.25.2.3.1.5": {Value: 4063232},                 // hrStorageSize (blocos)
		".1.3.6.1.2.1.25.2.3.1.6": {Value: 709376},                  // hrStorageUsed (blocos)
	}
	tags := map[string]string{}
	factor := enrichHrStorageRow(hrStorageTableOID, ram, tags)
	if factor != 1024 {
		t.Fatalf("fator de bloco = %v, esperado 1024", factor)
	}
	if tags["storage_type"] != "ram" {
		t.Fatalf("storage_type = %q, esperado ram", tags["storage_type"])
	}
	if tags["storage_descr"] != "main memory" {
		t.Fatalf("storage_descr = %q, esperado \"main memory\"", tags["storage_descr"])
	}
	// size × fator = bytes reais (4063232 blocos × 1024 = 4,16 GB), não 4 MB.
	if got := 4063232.0 * factor; got != 4160749568.0 {
		t.Fatalf("size em bytes = %v, esperado 4160749568", got)
	}

	// Disco: type=hrStorageFixedDisk.
	disk := map[string]gosnmp.SnmpPDU{
		".1.3.6.1.2.1.25.2.3.1.2": {Value: "1.3.6.1.2.1.25.2.1.4"}, // sem leading dot, tolerado
		".1.3.6.1.2.1.25.2.3.1.4": {Value: 4096},
	}
	dtags := map[string]string{}
	if f := enrichHrStorageRow(hrStorageTableOID, disk, dtags); f != 4096 {
		t.Fatalf("fator disco = %v, esperado 4096", f)
	}
	if dtags["storage_type"] != "fixed_disk" {
		t.Fatalf("storage_type disco = %q, esperado fixed_disk", dtags["storage_type"])
	}

	// Tabela que NÃO é hrStorage → no-op (fator 1, sem rótulos).
	other := map[string]string{}
	if f := enrichHrStorageRow("1.3.6.1.2.1.2.2", ram, other); f != 1 {
		t.Fatalf("fator fora do hrStorage = %v, esperado 1", f)
	}
	if len(other) != 0 {
		t.Fatalf("não deveria rotular tabela não-hrStorage: %v", other)
	}

	// Sem unidade de alocação → fator 1 (degrada pra blocos, não pior que hoje).
	noAlloc := map[string]gosnmp.SnmpPDU{
		".1.3.6.1.2.1.25.2.3.1.2": {Value: ".1.3.6.1.2.1.25.2.1.2"},
	}
	if f := enrichHrStorageRow(hrStorageTableOID, noAlloc, map[string]string{}); f != 1 {
		t.Fatalf("fator sem alloc units = %v, esperado 1", f)
	}
}

func TestHrStorageTypeName(t *testing.T) {
	cases := map[string]string{
		"1.3.6.1.2.1.25.2.1.2":   "ram",
		".1.3.6.1.2.1.25.2.1.3":  "virtual_memory",
		"1.3.6.1.2.1.25.2.1.4":   "fixed_disk",
		"1.3.6.1.2.1.25.2.1.9":   "flash_memory",
		"1.3.6.1.2.1.25.2.1.10":  "network_disk",
		"1.3.6.1.2.1.25.2.1.99":  "", // desconhecido → vazio (não rotula)
		"":                       "",
	}
	for in, want := range cases {
		if got := hrStorageTypeName(in); got != want {
			t.Errorf("hrStorageTypeName(%q) = %q; esperado %q", in, got, want)
		}
	}
}

func TestIsHrStorageAmount(t *testing.T) {
	if !isHrStorageAmount("1.3.6.1.2.1.25.2.3.1.5") {
		t.Error("size (.5) deveria ser amount")
	}
	if !isHrStorageAmount(".1.3.6.1.2.1.25.2.3.1.6") {
		t.Error("used (.6) deveria ser amount")
	}
	if isHrStorageAmount("1.3.6.1.2.1.25.2.3.1.4") {
		t.Error("alloc units (.4) NÃO é amount")
	}
	if isHrStorageAmount("1.3.6.1.2.1.25.2.3.1.3") {
		t.Error("descr (.3) NÃO é amount")
	}
}
