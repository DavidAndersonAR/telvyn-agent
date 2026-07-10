package k8smeta

import "testing"

func TestWorkloadOf(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"deployment", "backend-7959f7697-z6psv", "backend"},
		{"deployment multi-word", "multi-word-app-6d4b9c7f8-x2k9p", "multi-word-app"},
		{"statefulset ordinal", "postgres-0", "postgres"},
		{"statefulset ordinal high", "kafka-12", "kafka"},
		{"daemonset pod-hash", "telvyn-agent-abcde", "telvyn-agent"},
		{"already workload", "backend", "backend"},
		{"single token", "a", "a"},
		{"empty", "", ""},
		// não confundir sufixo curto de nome com pod-hash:
		{"no suffix", "my-service", "my-service"},
	}
	for _, c := range cases {
		if got := WorkloadOf(c.in); got != c.want {
			t.Errorf("%s: WorkloadOf(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
