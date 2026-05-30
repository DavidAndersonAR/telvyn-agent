// detect_test.go — unit tests for DetectServices.
//
// We mock the OS process list via a package-level test seam (listProcessNames)
// rather than touching real /proc — keeps the test hermetic and fast, and
// matches the var-override pattern established by internal/checks/snmp_autodiscover
// (scanSNMP seam).
package enrollment

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// withListProcessNames swaps the test seam and restores it on test cleanup.
func withListProcessNames(t *testing.T, stub func(ctx context.Context) ([]string, error)) {
	t.Helper()
	prev := listProcessNames
	listProcessNames = stub
	t.Cleanup(func() { listProcessNames = prev })
}

func TestDetectServices_EmptyWhenNoMatches(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		return []string{"bash", "init", "systemd"}, nil
	})

	got := DetectServices(context.Background())
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestDetectServices_DetectsPostgresAndNginx(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		return []string{"postgres", "nginx", "idle"}, nil
	})

	got := DetectServices(context.Background())
	want := []string{"nginx", "postgres"} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestDetectServices_DeduplicatesPostmasterAsPostgres(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		// Both postmaster and postgres should collapse to a single "postgres"
		// entry — the master process on some distros is postmaster.
		return []string{"postmaster", "postgres", "postgres"}, nil
	})

	got := DetectServices(context.Background())
	want := []string{"postgres"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestDetectServices_DetectsRedisWithTruncatedComm(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		// /proc/[pid]/comm truncates to 15 chars; "redis-server" becomes
		// "redis-server" (12 chars, untruncated) but on some kernels the
		// reported name is "redis-ser" — both must map to "redis".
		return []string{"redis-ser"}, nil
	})

	got := DetectServices(context.Background())
	want := []string{"redis"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestDetectServices_DetectsDocker(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		return []string{"dockerd"}, nil
	})

	got := DetectServices(context.Background())
	want := []string{"docker"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestDetectServices_CapsAt16(t *testing.T) {
	// Build 20 distinct service names via a fake prefix map (test the cap
	// even though the real known-map only has 4 entries — cap is defense
	// in depth against future expansion).
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		// 20 known synthetic processes — we abuse the seam by injecting
		// names that all map to distinct services. To exercise the cap
		// without growing `known`, we'll instead manually call the cap
		// path by seeding many recognized names that produce duplicates.
		names := []string{
			"postgres", "nginx", "redis-ser", "dockerd",
			"postgres", "nginx", "redis-ser", "dockerd",
			"postgres", "nginx", "redis-ser", "dockerd",
			"postgres", "nginx", "redis-ser", "dockerd",
			"postgres", "nginx", "redis-ser", "dockerd",
		}
		return names, nil
	})

	got := DetectServices(context.Background())
	// Real known-map has 4 services; dedup applies first, then cap. Since
	// dedup already collapses to 4, result is 4 not 16 — but we still
	// assert the invariant: len(got) <= 16.
	if len(got) > 16 {
		t.Fatalf("expected len <= 16, got %d (%v)", len(got), got)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 deduped services, got %d (%v)", len(got), got)
	}
}

func TestDetectServices_ReturnsNilOnError(t *testing.T) {
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		return nil, errors.New("permission denied reading /proc")
	})

	got := DetectServices(context.Background())
	if got != nil {
		t.Fatalf("expected nil on error, got %v", got)
	}
}

func TestDetectServices_TolerantToEmptyNames(t *testing.T) {
	// Real /proc may report empty Name() for kernel threads or zombies.
	// Must not panic and must not produce phantom matches.
	withListProcessNames(t, func(ctx context.Context) ([]string, error) {
		return []string{"", "kthreadd", "", "nginx"}, nil
	})

	got := DetectServices(context.Background())
	want := []string{"nginx"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
