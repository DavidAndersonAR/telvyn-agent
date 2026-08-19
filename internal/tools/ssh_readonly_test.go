package tools

import "testing"

func TestValidateReadOnlySSHCommand(t *testing.T) {
	allowed := []struct{ vendor, command string }{
		{"cisco", "show interfaces"}, {"huawei", "display current-configuration"},
		{"mikrotik", "/interface print"}, {"juniper", "show route"},
		{"fortinet", "get system status"},
	}
	for _, tc := range allowed {
		if err := ValidateReadOnlySSHCommand(tc.vendor, tc.command); err != nil {
			t.Fatalf("expected %q/%q to pass: %v", tc.vendor, tc.command, err)
		}
	}
	blocked := []struct{ vendor, command string }{
		{"cisco", "configure terminal"}, {"cisco", "show clock; reload"},
		{"huawei", "system-view"}, {"mikrotik", "/system reboot"},
		{"unknown", "show version"},
	}
	for _, tc := range blocked {
		if err := ValidateReadOnlySSHCommand(tc.vendor, tc.command); err == nil {
			t.Fatalf("expected %q/%q to be blocked", tc.vendor, tc.command)
		}
	}
}
