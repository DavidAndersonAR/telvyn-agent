package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestAuthProto(t *testing.T) {
	cases := []struct {
		in      string
		want    gosnmp.SnmpV3AuthProtocol
		wantErr bool
	}{
		{"NoAuth", gosnmp.NoAuth, false},
		{"noauth", gosnmp.NoAuth, false},
		{"MD5", gosnmp.MD5, false},
		{"md5", gosnmp.MD5, false},
		{"SHA", gosnmp.SHA, false},
		{"SHA224", gosnmp.SHA224, false},
		{"SHA256", gosnmp.SHA256, false},
		{"sha256", gosnmp.SHA256, false},
		{"SHA384", gosnmp.SHA384, false},
		{"SHA512", gosnmp.SHA512, false},
		{"", 0, true},
		{"BLAKE3", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := AuthProto(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("AuthProto(%q)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPrivProto(t *testing.T) {
	cases := []struct {
		in      string
		want    gosnmp.SnmpV3PrivProtocol
		wantErr bool
	}{
		{"NoPriv", gosnmp.NoPriv, false},
		{"nopriv", gosnmp.NoPriv, false},
		{"DES", gosnmp.DES, false},
		{"AES", gosnmp.AES, false},
		{"AES192", gosnmp.AES192, false},
		{"AES256", gosnmp.AES256, false},
		{"AES192C", gosnmp.AES192C, false},
		{"AES256C", gosnmp.AES256C, false},
		{"aes256c", gosnmp.AES256C, false},
		{"", 0, true},
		{"AES512", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := PrivProto(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("PrivProto(%q)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestMsgFlags(t *testing.T) {
	cases := []struct {
		name     string
		auth     gosnmp.SnmpV3AuthProtocol
		priv     gosnmp.SnmpV3PrivProtocol
		want     gosnmp.SnmpV3MsgFlags
		wantErr  bool
	}{
		{"noauth-nopriv", gosnmp.NoAuth, gosnmp.NoPriv, gosnmp.NoAuthNoPriv, false},
		{"auth-nopriv", gosnmp.SHA256, gosnmp.NoPriv, gosnmp.AuthNoPriv, false},
		{"auth-priv", gosnmp.SHA256, gosnmp.AES256, gosnmp.AuthPriv, false},
		{"noauth-priv-rejected", gosnmp.NoAuth, gosnmp.AES256, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MsgFlags(tc.auth, tc.priv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
