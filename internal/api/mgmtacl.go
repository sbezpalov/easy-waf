// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// ValidateManagementCIDRs checks the allowlist used for management GUI/API (same rules as settings save).
func ValidateManagementCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("management_allowed_cidrs: at least one CIDR is required")
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			return fmt.Errorf("management_allowed_cidrs: empty entry")
		}
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("management_allowed_cidrs: invalid CIDR %q: %w", c, err)
		}
	}
	return nil
}

// clientIP returns the client address used for management ACL and login rate limiting.
//
// After TrustedRealIP, RemoteAddr is either the direct TCP peer or a header-derived
// client IP (IP only, no ":port") when the peer is a trusted reverse proxy.
// Direct TCP connections use "host:port" (IPv6 bracketed). Both forms must parse here.
func clientIP(r *http.Request) (netip.Addr, bool) {
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		return ip, true
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

func ipAllowed(ip netip.Addr, cidrs []string) bool {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) managementACL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if os.Getenv("EASY_WAF_BYPASS_MGMT_ACL") == "1" {
			next.ServeHTTP(w, r)
			return
		}
		cidrs := s.Eng.Settings().ManagementAllowedCIDRs
		if len(cidrs) == 0 {
			cidrs = config.DefaultManagementCIDRs()
		}
		ip, ok := clientIP(r)
		if !ok || !ipAllowed(ip, cidrs) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"management access denied for this source address"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
