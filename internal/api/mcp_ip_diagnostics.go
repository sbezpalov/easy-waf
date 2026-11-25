// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type mcpIPBlockingEvidence struct {
	IP                    string `json:"ip"`
	LocalAllowlistMatches *int   `json:"local_allowlist_matches"`
	LocalBlocklistMatches *int   `json:"enabled_local_blocklist_matches"`
	GeoIPCountry          string `json:"cached_geoip_country,omitempty"`
	CrowdSecBan           string `json:"crowdsec_ban"`
	RequestObservation    string `json:"request_observation"`
}

func (s *Server) getMCPIPBlockingEvidence(w http.ResponseWriter, r *http.Request) {
	raw, ok := mcpQueryValue(r, "ip")
	ip, err := netip.ParseAddr(raw)
	if !ok || err != nil || ip.Zone() != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one IPv4 or IPv6 address is required"})
		return
	}
	ip = ip.Unmap()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	result := mcpIPBlockingEvidence{
		IP: ip.String(), RequestObservation: "not_checked",
		GeoIPCountry: s.mcpCachedCountry(ip),
	}
	result.LocalAllowlistMatches, result.LocalBlocklistMatches = s.mcpLocalIPMatches(ctx, net.IP(ip.AsSlice()))
	result.CrowdSecBan = s.mcpCrowdSecBan(ctx, ip)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) mcpLocalIPMatches(ctx context.Context, ip net.IP) (allow, block *int) {
	st := s.Eng.Store
	if st == nil {
		return nil, nil
	}
	if rows, err := st.ListIPWLLocal(ctx); err == nil {
		matches := 0
		for _, row := range rows {
			if mcpIPMatches(ip, row.CIDR) {
				matches++
			}
		}
		allow = &matches
	}
	if rows, err := st.ListIPBLLocal(ctx); err == nil {
		matches := 0
		for _, row := range rows {
			if row.Enabled && mcpIPMatches(ip, row.CIDR) {
				matches++
			}
		}
		block = &matches
	}
	return allow, block
}

func mcpIPMatches(ip net.IP, entry string) bool {
	entry = strings.TrimSpace(entry)
	if _, prefix, err := net.ParseCIDR(entry); err == nil {
		return prefix.Contains(ip)
	}
	return net.ParseIP(entry).Equal(ip)
}

func (s *Server) mcpCachedCountry(ip netip.Addr) string {
	geo := s.Eng.GeoIP()
	if geo == nil || geo.Cache == nil || !s.Eng.Settings().GeoIPEnabled {
		return ""
	}
	code, ok := geo.Cache.Peek(ip.String())
	if !ok || len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

func (s *Server) mcpCrowdSecBan(ctx context.Context, ip netip.Addr) string {
	client, err := s.crowdsecLAPIClient()
	if err != nil {
		return "unavailable"
	}
	if client.APIKey == "" {
		return "not_configured"
	}
	match, err := client.HasIPBan(ctx, ip)
	if err != nil {
		return "unavailable"
	}
	if match {
		return "present"
	}
	return "absent"
}
