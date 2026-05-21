package ipbl

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestPrivateOrSpecial(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"192.168.1.1", "172.16.0.1", "fe80::1",
	}
	for _, s := range blocked {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if !privateOrSpecial(ip) {
			t.Fatalf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.1"}
	for _, s := range allowed {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if privateOrSpecial(ip) {
			t.Fatalf("%s should be allowed", s)
		}
	}
}

func TestValidateFeedURL_literalBlocked(t *testing.T) {
	ctx := context.Background()
	cases := []string{
		"http://127.0.0.1/x",
		"http://169.254.169.254/",
		"http://10.0.0.5/list",
		"http://192.168.1.1/list.txt",
	}
	for _, raw := range cases {
		_, err := ValidateFeedURLContext(ctx, raw, false)
		if err == nil {
			t.Fatalf("%s: expected error", raw)
		}
		if !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("%s: got %v", raw, err)
		}
	}
}

func TestValidateFeedURL_scheme(t *testing.T) {
	_, err := ValidateFeedURL("ftp://127.0.0.1/x", false)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateFeedURL_allowPrivateLab(t *testing.T) {
	u, err := ValidateFeedURL("http://127.0.0.1/list", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "127.0.0.1" {
		t.Fatalf("host %q", u.Host)
	}
}

func TestValidateFeedURL_publicLiteral(t *testing.T) {
	u, err := ValidateFeedURL("https://203.0.113.10/list.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "203.0.113.10" {
		t.Fatalf("host %q", u.Hostname())
	}
}
