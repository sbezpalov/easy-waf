package diag

import (
	"context"
	"strings"
	"testing"
)

func TestTrace_rejectsInjectionHosts(t *testing.T) {
	ctx := context.Background()
	for _, host := range []string{"-T", "--port=22", "; rm", "host;id", ""} {
		_, err := Trace(ctx, host)
		if err == nil {
			t.Fatalf("Trace(%q): expected error", host)
		}
		if !strings.Contains(err.Error(), "invalid host") {
			t.Fatalf("Trace(%q): got %v", host, err)
		}
	}
}

func TestPing_rejectsInjectionHosts(t *testing.T) {
	ctx := context.Background()
	for _, host := range []string{"-T", "--port=22", "; rm"} {
		_, err := Ping(ctx, host, 4)
		if err == nil {
			t.Fatalf("Ping(%q): expected error", host)
		}
	}
}

func TestIsHostname_valid(t *testing.T) {
	for _, h := range []string{"example.com", "a.b", "host-1.local"} {
		if !isHostname(h) {
			t.Fatalf("expected valid hostname %q", h)
		}
	}
}

func TestIsHostname_invalid(t *testing.T) {
	for _, h := range []string{"-T", "", ".bad", "bad..host", "a..b"} {
		if isHostname(h) {
			t.Fatalf("expected invalid hostname %q", h)
		}
	}
}
