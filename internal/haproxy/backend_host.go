// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"fmt"
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

// formatBackendAddr returns host:port for HAProxy server lines, bracketing IPv6.
func formatBackendAddr(host string, port int) string {
	host = strings.TrimSpace(host)
	bare := strings.Trim(host, "[]")
	if ip := net.ParseIP(bare); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", bare, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
