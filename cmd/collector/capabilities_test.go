package main

import (
	"reflect"
	"testing"
)

func TestCollectorCapabilitiesForSnmpAgent(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "snmp")
	t.Setenv("ISPWATCH_SNMP", "1")
	t.Setenv("ISPWATCH_ICMP", "true")
	t.Setenv("ISPWATCH_LLDP", "0")
	t.Setenv("ISPWATCH_SSH", "off")

	want := []string{"metrics", "checks", "snmp", "icmp"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("collectorCapabilities() = %v, want %v", got, want)
	}
}

func TestCollectorCapabilitiesForNonSnmpAgent(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "linux")
	t.Setenv("ISPWATCH_ICMP", "1")

	want := []string{"metrics", "checks"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("collectorCapabilities() = %v, want %v", got, want)
	}
}

func TestCollectorInstallModeUsesExplicitRuntime(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "snmp")
	t.Setenv("ISPWATCH_INSTALL_MODE", "docker")
	if got := collectorInstallMode(); got != "docker" {
		t.Fatalf("collectorInstallMode() = %q, want docker", got)
	}
}
