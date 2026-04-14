package api

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestClientIP_DirectTCPWithPort(t *testing.T) {
	r := &http.Request{RemoteAddr: "192.0.2.10:12345"}
	ip, ok := clientIP(r)
	if !ok || ip.String() != "192.0.2.10" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}

func TestClientIP_ChiRealIPNoPort(t *testing.T) {
	// middleware.RealIP sets RemoteAddr to the header-derived IP only.
	r := &http.Request{RemoteAddr: "192.0.2.20"}
	ip, ok := clientIP(r)
	if !ok || ip.String() != "192.0.2.20" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}

func TestClientIP_IPv6Bracketed(t *testing.T) {
	r := &http.Request{RemoteAddr: "[2001:db8::1]:8443"}
	ip, ok := clientIP(r)
	if !ok || ip.String() != "2001:db8::1" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}

func TestIPAllowed(t *testing.T) {
	cidrs := []string{"127.0.0.0/8", "192.168.1.0/24"}
	ip := netip.MustParseAddr("192.168.1.50")
	if !ipAllowed(ip, cidrs) {
		t.Fatal("expected LAN IP allowed")
	}
	ip2 := netip.MustParseAddr("8.8.8.8")
	if ipAllowed(ip2, cidrs) {
		t.Fatal("expected WAN IP denied")
	}
}

func TestValidateManagementCIDRs(t *testing.T) {
	if err := validateManagementCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := validateManagementCIDRs([]string{}); err == nil {
		t.Fatal("expected error for empty list")
	}
	if err := validateManagementCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}
