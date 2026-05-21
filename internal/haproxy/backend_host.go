package haproxy

import (
	"net"
	"net/netip"
	"strings"
)

// backendHostIsLiteralIP reports whether backend_host is an IP address (not a DNS name).
func backendHostIsLiteralIP(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.Contains(host, "%") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsValid() {
		return true
	}
	return false
}
