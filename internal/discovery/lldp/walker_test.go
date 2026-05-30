package lldp

import "testing"

func TestNeighborKey(t *testing.T) {
	cases := []struct {
		oid  string
		want string
	}{
		{"1.0.8802.1.1.2.1.4.1.1.5.0.10.1", "10.1"},
		{".1.0.8802.1.1.2.1.4.1.1.5.0.10.1", "10.1"},
		{"1.0.8802.1.1.2.1.4.1.1.9.123.1.7", "1.7"},
		{"1.2.3", "2.3"},
		{"", ""},
	}
	for _, c := range cases {
		if got := neighborKey(c.oid); got != c.want {
			t.Errorf("neighborKey(%q) = %q, want %q", c.oid, got, c.want)
		}
	}
}

func TestSplitNeighborKey(t *testing.T) {
	a, b := splitNeighborKey("10.7")
	if a != 10 || b != 7 {
		t.Errorf("splitNeighborKey(10.7) = (%d, %d), want (10, 7)", a, b)
	}
	a, b = splitNeighborKey("bad")
	if a != 0 || b != 0 {
		t.Errorf("splitNeighborKey(bad) = (%d, %d), want (0, 0)", a, b)
	}
}

func TestFormatIdMACAddress(t *testing.T) {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	got := formatId(ChassisIdSubtypeMACAddress, mac)
	if got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("formatId(MAC, %v) = %q, want aa:bb:cc:dd:ee:ff", mac, got)
	}
}

func TestFormatIdIfName(t *testing.T) {
	got := formatId(ChassisIdSubtypeIfName, []byte("Gi0/1"))
	if got != "Gi0/1" {
		t.Errorf("formatId(IfName, Gi0/1) = %q, want Gi0/1", got)
	}
}

func TestFormatIdNonPrintableFallsToHex(t *testing.T) {
	got := formatId(ChassisIdSubtypeLocal, []byte{0x01, 0x02, 0xff})
	if got != "01:02:ff" {
		t.Errorf("formatId(Local, [01 02 ff]) = %q, want 01:02:ff", got)
	}
}

func TestLastUint32(t *testing.T) {
	v, ok := lastUint32("1.3.6.1.2.1.2.2.1.5.42")
	if !ok || v != 42 {
		t.Errorf("lastUint32(...5.42) = %d, %v; want 42, true", v, ok)
	}
	v, ok = lastUint32(".1.2.3.10")
	if !ok || v != 10 {
		t.Errorf("lastUint32(.1.2.3.10) = %d, %v; want 10, true", v, ok)
	}
	if _, ok := lastUint32("oops"); ok {
		t.Errorf("lastUint32(oops) should fail")
	}
}
