package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestWalkTable_IfTableSimpleIndex(t *testing.T) {
	// ifTable = .1.3.6.1.2.1.2.2; entries have form
	// .1.3.6.1.2.1.2.2.1.<col>.<rowIndex>
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: int(1)},
			{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: []byte("eth0")},
			{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint(100)},
			{Name: ".1.3.6.1.2.1.2.2.1.16.1", Type: gosnmp.Counter32, Value: uint(200)},
			{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: int(2)},
			{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: gosnmp.OctetString, Value: []byte("eth1")},
			{Name: ".1.3.6.1.2.1.2.2.1.10.2", Type: gosnmp.Counter32, Value: uint(300)},
			{Name: ".1.3.6.1.2.1.2.2.1.16.2", Type: gosnmp.Counter32, Value: uint(400)},
		},
	}
	c := newClientWithDriver(fake, "x:161")

	rows, err := WalkTable(nil, c, "1.3.6.1.2.1.2.2")
	if err != nil {
		t.Fatalf("WalkTable: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	row1, ok := rows["1"]
	if !ok {
		t.Fatalf("missing rowIndex=1; got keys %v", keys(rows))
	}
	if len(row1) != 4 {
		t.Fatalf("row1 has %d cols want 4", len(row1))
	}
	in, ok := row1[".1.3.6.1.2.1.2.2.1.10"]
	if !ok {
		t.Fatalf("missing col .1.10 in row1: %v", colKeys(row1))
	}
	if v, _ := PduFloat(in); v != 100 {
		t.Fatalf("ifInOctets row1 = %v want 100", v)
	}
}

func TestWalkTable_CompositeRowIndex(t *testing.T) {
	// ipAddrEntry indexed by IPv4 (composite rowIndex)
	// .1.3.6.1.2.1.4.20.1.<col>.<a>.<b>.<c>.<d>
	root := "1.3.6.1.2.1.4.20"
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.4.20.1.1.10.0.0.1", Type: gosnmp.IPAddress, Value: "10.0.0.1"},
			{Name: ".1.3.6.1.2.1.4.20.1.2.10.0.0.1", Type: gosnmp.Integer, Value: int(2)},
			{Name: ".1.3.6.1.2.1.4.20.1.1.192.168.1.1", Type: gosnmp.IPAddress, Value: "192.168.1.1"},
			{Name: ".1.3.6.1.2.1.4.20.1.2.192.168.1.1", Type: gosnmp.Integer, Value: int(3)},
		},
	}
	c := newClientWithDriver(fake, "x:161")
	rows, err := WalkTable(nil, c, root)
	if err != nil {
		t.Fatalf("WalkTable: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2 keys %v", len(rows), keys(rows))
	}
	if _, ok := rows["10.0.0.1"]; !ok {
		t.Fatalf("missing rowIndex 10.0.0.1, keys=%v", keys(rows))
	}
	if _, ok := rows["192.168.1.1"]; !ok {
		t.Fatalf("missing rowIndex 192.168.1.1, keys=%v", keys(rows))
	}
}

func TestWalkTable_SkipsOutOfRoot(t *testing.T) {
	root := "1.3.6.1.2.1.2.2"
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: int(1)},
			{Name: ".1.3.6.1.2.1.999.0", Type: gosnmp.Integer, Value: int(99)}, // alien
		},
	}
	c := newClientWithDriver(fake, "x:161")
	rows, err := WalkTable(nil, c, root)
	if err != nil {
		t.Fatalf("WalkTable: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 (alien must be skipped)", len(rows))
	}
}

func TestWalkTable_AcceptsRootWithLeadingDot(t *testing.T) {
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: int(1)},
		},
	}
	c := newClientWithDriver(fake, "x:161")
	rows, err := WalkTable(nil, c, ".1.3.6.1.2.1.2.2")
	if err != nil {
		t.Fatalf("WalkTable: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
}

func keys(m map[string]map[string]gosnmp.SnmpPDU) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func colKeys(m map[string]gosnmp.SnmpPDU) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
