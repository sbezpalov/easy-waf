package ipbl

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestHardBlocked_always(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "fe80::1", "100.64.0.1"} {
		ip := netip.MustParseAddr(s)
		if !hardBlocked(ip) {
			t.Fatalf("%s should be hard-blocked", s)
		}
	}
}

func TestSoftBlocked_public(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.10"} {
		ip := netip.MustParseAddr(s)
		if hardBlocked(ip) || softBlocked(ip) {
			t.Fatalf("%s should be public", s)
		}
	}
}

func TestCheckDestIP_hardOverridesAllowlist(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if err := checkDestIP(netip.MustParseAddr("127.0.0.1"), allowed); err == nil {
		t.Fatal("127.0.0.1 must stay hard-blocked even with 127.0.0.0/8 allowlist")
	}
}

func TestCheckDestIP_softAllowlist(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	if err := checkDestIP(netip.MustParseAddr("192.168.1.10"), allowed); err != nil {
		t.Fatal(err)
	}
	if err := checkDestIP(netip.MustParseAddr("192.168.2.1"), allowed); err == nil {
		t.Fatal("192.168.2.1 should be blocked outside allowlist")
	}
}

func TestValidateFeedURL_literalBlocked(t *testing.T) {
	ctx := context.Background()
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	for _, raw := range []string{
		"http://127.0.0.1/x",
		"http://169.254.169.254/",
		"http://10.0.0.5/list",
	} {
		_, err := ValidateFeedURLContext(ctx, raw, allowed)
		if err == nil {
			t.Fatalf("%s: expected error", raw)
		}
	}
	_, err := ValidateFeedURLContext(ctx, "http://192.168.1.50/list.txt", allowed)
	if err != nil {
		t.Fatalf("192.168.1.50 in allowlist: %v", err)
	}
}

func TestValidateFeedURL_scheme(t *testing.T) {
	_, err := ValidateFeedURLContext(context.Background(), "ftp://203.0.113.1/x", nil)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateFeedURL_publicLiteral(t *testing.T) {
	u, err := ValidateFeedURLContext(context.Background(), "https://203.0.113.10/list.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "203.0.113.10" {
		t.Fatalf("host %q", u.Hostname())
	}
}

func TestParseFeedAllowedPrefixes_deprecatedRFC1918(t *testing.T) {
	p := ParseFeedAllowedPrefixes(config.GlobalSettings{IPBLAllowPrivateFetch: true})
	if len(p) != 3 {
		t.Fatalf("got %d prefixes", len(p))
	}
}
