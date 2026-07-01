package main

import (
	"net"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestBuildTrapPayload_V2c(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
			{Name: "1.3.6.1.2.1.2.2.1.1.6", Type: gosnmp.Integer, Value: 6},
			{Name: "1.3.6.1.2.1.31.1.1.1.1.6", Type: gosnmp.OctetString, Value: []byte("ether6")},
		},
	}
	u := &net.UDPAddr{IP: net.ParseIP("45.6.188.40"), Port: 40000}
	trap := buildTrapPayload(pkt, u)
	if trap == nil {
		t.Fatal("trap nil")
	}
	if trap["trap_oid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap_oid = %v, quero linkDown", trap["trap_oid"])
	}
	if trap["source_ip"] != "45.6.188.40" {
		t.Errorf("source_ip = %v", trap["source_ip"])
	}
	vb, ok := trap["varbinds"].(map[string]string)
	if !ok {
		t.Fatalf("varbinds tipo errado: %T", trap["varbinds"])
	}
	if vb["1.3.6.1.2.1.31.1.1.1.1.6"] != "ether6" {
		t.Errorf("ifDescr = %v, quero ether6", vb["1.3.6.1.2.1.31.1.1.1.1.6"])
	}
	// o snmpTrapOID.0 NÃO deve virar varbind (foi consumido pra trap_oid)
	if _, dup := vb["1.3.6.1.6.3.1.1.4.1.0"]; dup {
		t.Error("snmpTrapOID.0 vazou pros varbinds")
	}
}

func TestV1TrapOID(t *testing.T) {
	cases := map[int]string{
		0: "1.3.6.1.6.3.1.1.5.1", // coldStart
		2: "1.3.6.1.6.3.1.1.5.3", // linkDown
		4: "1.3.6.1.6.3.1.1.5.5", // authFailure
	}
	for generic, want := range cases {
		// GenericTrap/Enterprise/SpecificTrap moram no struct embutido SnmpTrap.
		pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: generic}}
		if got := v1TrapOID(pkt); got != want {
			t.Errorf("generic=%d → %s, quero %s", generic, got, want)
		}
	}
	// enterpriseSpecific (generic=6) → enterprise.0.specific
	ent := &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: 6, Enterprise: ".1.3.6.1.4.1.14988", SpecificTrap: 5}}
	if got := v1TrapOID(ent); got != "1.3.6.1.4.1.14988.0.5" {
		t.Errorf("enterpriseSpecific → %s, quero 1.3.6.1.4.1.14988.0.5", got)
	}
	// v2c não deve derivar OID v1
	if got := v1TrapOID(&gosnmp.SnmpPacket{Version: gosnmp.Version2c}); got != "" {
		t.Errorf("v2c v1TrapOID = %q, quero vazio", got)
	}
}

func TestPduToString(t *testing.T) {
	if s := pduToString(gosnmp.SnmpPDU{Value: []byte("abc")}); s != "abc" {
		t.Errorf("bytes → %q", s)
	}
	if s := pduToString(gosnmp.SnmpPDU{Value: 42}); s != "42" {
		t.Errorf("int → %q", s)
	}
}
