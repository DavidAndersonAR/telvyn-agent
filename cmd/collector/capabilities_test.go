package main

import (
	"reflect"
	"testing"
)

func TestAdvertisedCollectorCapabilitiesForSnmp(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "snmp")
	t.Setenv("ISPWATCH_CHECKS_ENABLED", "1")
	t.Setenv("ISPWATCH_SNMP", "1")
	t.Setenv("ISPWATCH_ICMP", "1")
	t.Setenv("ISPWATCH_LLDP", "1")
	t.Setenv("ISPWATCH_SSH", "0")

	want := []string{"metrics", "checks", "snmp", "icmp", "lldp"}
	if got := advertisedCollectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
}

func TestAdvertisedCollectorCapabilitiesDoesNotGrantNetworkToHostAgent(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "linux")
	t.Setenv("ISPWATCH_CHECKS_ENABLED", "1")

	want := []string{"metrics", "checks"}
	if got := advertisedCollectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
}
