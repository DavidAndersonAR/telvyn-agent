package snmp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// fakeDriver implements snmpDriver for unit testing without a UDP socket.
type fakeDriver struct {
	connected     bool
	closed        bool
	getCalls      [][]string
	bulkCalls     []string
	getReturn     []gosnmp.SnmpPDU
	getErr        error
	bulkPDUs      []gosnmp.SnmpPDU
	bulkErr       error
	connectErr    error
	deadlineCalls int
}

func (f *fakeDriver) Connect() error {
	if f.connectErr != nil {
		return f.connectErr
	}
	f.connected = true
	return nil
}

func (f *fakeDriver) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	f.getCalls = append(f.getCalls, oids)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &gosnmp.SnmpPacket{Variables: f.getReturn}, nil
}

func (f *fakeDriver) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	f.bulkCalls = append(f.bulkCalls, root)
	if f.bulkErr != nil {
		return f.bulkErr
	}
	for _, pdu := range f.bulkPDUs {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

// Walk replays the same canned PDUs as BulkWalk — the fake doesn't distinguish
// GetBulk from GetNext, it just feeds the configured bulkPDUs to fn.
func (f *fakeDriver) Walk(root string, fn gosnmp.WalkFunc) error {
	f.bulkCalls = append(f.bulkCalls, root)
	if f.bulkErr != nil {
		return f.bulkErr
	}
	for _, pdu := range f.bulkPDUs {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeDriver) Close() error {
	f.closed = true
	return nil
}

func (f *fakeDriver) SetDeadline(t time.Time) error {
	f.deadlineCalls++
	return nil
}

func (f *fakeDriver) ConnReady() bool { return f.connected }

func TestNewClient_V2c(t *testing.T) {
	c, err := NewClient(Params{
		Version:   "v2c",
		Target:    "127.0.0.1:1161",
		Community: "public",
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Host() != "127.0.0.1" {
		t.Fatalf("Host=%q want 127.0.0.1", c.Host())
	}
	if c.Target() != "127.0.0.1:1161" {
		t.Fatalf("Target=%q", c.Target())
	}
	if c.snmp.Version != gosnmp.Version2c {
		t.Fatalf("Version=%v want v2c", c.snmp.Version)
	}
	if c.snmp.Community != "public" {
		t.Fatalf("Community=%q", c.snmp.Community)
	}
	if c.snmp.Port != 1161 {
		t.Fatalf("Port=%d want 1161", c.snmp.Port)
	}
}

func TestNewClient_V2c_DefaultPort(t *testing.T) {
	c, err := NewClient(Params{Version: "v2c", Target: "10.0.0.1", Community: "x"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.snmp.Port != 161 {
		t.Fatalf("Port=%d want 161 default", c.snmp.Port)
	}
	if c.snmp.Timeout <= 0 {
		t.Fatalf("Timeout must default to a positive duration, got %v", c.snmp.Timeout)
	}
}

func TestNewClient_V3_AuthPriv(t *testing.T) {
	c, err := NewClient(Params{
		Version:     "v3",
		Target:      "10.0.0.1",
		V3User:      "monitoring",
		V3AuthProto: "SHA256",
		V3AuthPass:  "authpass1",
		V3PrivProto: "AES256",
		V3PrivPass:  "privpass1",
	})
	if err != nil {
		t.Fatalf("NewClient v3: %v", err)
	}
	if c.snmp.Version != gosnmp.Version3 {
		t.Fatalf("Version=%v want v3", c.snmp.Version)
	}
	if c.snmp.SecurityModel != gosnmp.UserSecurityModel {
		t.Fatalf("SecurityModel=%v", c.snmp.SecurityModel)
	}
	if c.snmp.MsgFlags != gosnmp.AuthPriv {
		t.Fatalf("MsgFlags=%v want AuthPriv", c.snmp.MsgFlags)
	}
	usm, ok := c.snmp.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatalf("SecurityParameters not *UsmSecurityParameters")
	}
	if usm.UserName != "monitoring" {
		t.Fatalf("UserName=%q", usm.UserName)
	}
	if usm.AuthenticationProtocol != gosnmp.SHA256 {
		t.Fatalf("AuthProto=%v want SHA256", usm.AuthenticationProtocol)
	}
	if usm.PrivacyProtocol != gosnmp.AES256 {
		t.Fatalf("PrivProto=%v want AES256", usm.PrivacyProtocol)
	}
	if usm.AuthenticationPassphrase != "authpass1" {
		t.Fatalf("AuthPass mismatch")
	}
	if usm.PrivacyPassphrase != "privpass1" {
		t.Fatalf("PrivPass mismatch")
	}
}

func TestNewClient_V3_Reeder_AES256C(t *testing.T) {
	c, err := NewClient(Params{
		Version:     "v3",
		Target:      "10.0.0.1",
		V3User:      "u",
		V3AuthProto: "SHA256",
		V3AuthPass:  "p",
		V3PrivProto: "AES256C",
		V3PrivPass:  "p",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	usm := c.snmp.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if usm.PrivacyProtocol != gosnmp.AES256C {
		t.Fatalf("PrivProto=%v want AES256C (Cisco/Blumenthal-C variant)", usm.PrivacyProtocol)
	}
}

func TestNewClient_V3_NoAuthNoPriv(t *testing.T) {
	c, err := NewClient(Params{
		Version:     "v3",
		Target:      "10.0.0.1",
		V3User:      "u",
		V3AuthProto: "NoAuth",
		V3PrivProto: "NoPriv",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.snmp.MsgFlags != gosnmp.NoAuthNoPriv {
		t.Fatalf("MsgFlags=%v want NoAuthNoPriv", c.snmp.MsgFlags)
	}
}

func TestNewClient_V3_NoAuthPriv_Rejected(t *testing.T) {
	_, err := NewClient(Params{
		Version:     "v3",
		Target:      "10.0.0.1",
		V3User:      "u",
		V3AuthProto: "NoAuth",
		V3PrivProto: "AES256",
	})
	if err == nil {
		t.Fatalf("expected error for NoAuth+Priv combination (USM RFC 3414)")
	}
}

func TestNewClient_InvalidVersion(t *testing.T) {
	_, err := NewClient(Params{Version: "v4", Target: "x", Community: "y"})
	if err == nil {
		t.Fatalf("expected error for unknown version")
	}
}

func TestNewClient_EmptyTarget(t *testing.T) {
	_, err := NewClient(Params{Version: "v2c", Community: "x"})
	if err == nil {
		t.Fatalf("expected error for empty target")
	}
}

func TestNewClient_DefaultVersionIsV2c(t *testing.T) {
	c, err := NewClient(Params{Target: "10.0.0.1", Community: "x"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.snmp.Version != gosnmp.Version2c {
		t.Fatalf("expected default v2c, got %v", c.snmp.Version)
	}
}

func TestClient_Get_UsesDriver(t *testing.T) {
	want := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("router-a")},
	}
	fake := &fakeDriver{getReturn: want}
	c := newClientWithDriver(fake, "10.0.0.1:161")

	pdus, err := c.Get(context.Background(), []string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(pdus) != 1 || pdus[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("unexpected pdus: %#v", pdus)
	}
	if len(fake.getCalls) != 1 {
		t.Fatalf("Get not invoked on driver")
	}
}

func TestClient_Get_PropagatesError(t *testing.T) {
	fake := &fakeDriver{getErr: errors.New("timeout")}
	c := newClientWithDriver(fake, "10.0.0.1:161")
	if _, err := c.Get(context.Background(), []string{"1.3"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_BulkWalk_Collects(t *testing.T) {
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: int(1)},
			{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: int(2)},
		},
	}
	c := newClientWithDriver(fake, "x:161")
	var got []gosnmp.SnmpPDU
	err := c.BulkWalk(context.Background(), "1.3.6.1.2.1.2.2", func(p gosnmp.SnmpPDU) error {
		got = append(got, p)
		return nil
	})
	if err != nil {
		t.Fatalf("BulkWalk: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d pdus want 2", len(got))
	}
}

func TestClient_WalkAll(t *testing.T) {
	fake := &fakeDriver{
		bulkPDUs: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: int(1)},
			{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: int(2)},
		},
	}
	c := newClientWithDriver(fake, "x:161")
	pdus, err := c.WalkAll(context.Background(), "1.3.6.1.2.1.2.2")
	if err != nil {
		t.Fatalf("WalkAll: %v", err)
	}
	if len(pdus) != 2 {
		t.Fatalf("len=%d want 2", len(pdus))
	}
}

func TestClient_CloseIdempotent(t *testing.T) {
	fake := &fakeDriver{}
	c := newClientWithDriver(fake, "x:161")
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close should be no-op, got %v", err)
	}
}

func TestPduFloat(t *testing.T) {
	cases := []struct {
		name   string
		pdu    gosnmp.SnmpPDU
		want   float64
		wantOK bool
	}{
		{"counter32", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(123)}, 123, true},
		{"counter64", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(987654321)}, 987654321, true},
		{"gauge32", gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint32(42)}, 42, true},
		{"integer", gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: int(7)}, 7, true},
		{"octet skipped", gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("eth0")}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := PduFloat(tc.pdu)
			if ok != tc.wantOK || (ok && v != tc.want) {
				t.Errorf("got (%v,%v), want (%v,%v)", v, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort uint16
		ok       bool
	}{
		{"10.0.0.1", "10.0.0.1", 161, true},
		{"10.0.0.1:1161", "10.0.0.1", 1161, true},
		{"  router.x  ", "router.x", 161, true},
		{"", "", 0, false},
		{":161", "", 0, false},
		{"x:abc", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			h, p, ok := splitHostPort(tc.in)
			if ok != tc.ok || (ok && (h != tc.wantHost || p != tc.wantPort)) {
				t.Errorf("got (%q,%d,%v) want (%q,%d,%v)", h, p, ok, tc.wantHost, tc.wantPort, tc.ok)
			}
		})
	}
}
