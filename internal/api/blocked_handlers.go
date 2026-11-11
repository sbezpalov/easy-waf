// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/host/journal"
)

// readBlockedJournal is replaced in tests.
var readBlockedJournal = journal.ReadBlocked

var blockedPeriods = map[string]time.Duration{
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

const (
	blockedDefaultLimit = 200
	blockedMaxLimit     = 1000
	blockedTopN         = 10
)

type blockedResponse struct {
	Period string    `json:"period"`
	Since  time.Time `json:"since"`
	// Truncated means the journal had more matches than one read returns, so
	// counts cover only the newest of them.
	Truncated bool             `json:"truncated"`
	Summary   blocklog.Summary `json:"summary"`
	Events    []blocklog.Event `json:"events"`
}

// listBlocked serves GET /security/blocked: requests the edge refused, from the
// haproxy.service journal.
func (s *Server) listBlocked(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	d, ok := blockedPeriods[period]
	if !ok {
		http.Error(w, "period must be 1h, 24h or 7d", http.StatusBadRequest)
		return
	}
	limit := blockedDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > blockedMaxLimit {
			http.Error(w, "limit must be 1-1000", http.StatusBadRequest)
			return
		}
		limit = n
	}
	since := time.Now().Add(-d)
	out, err := readBlockedJournal(r.Context(), since, journal.BlockedLines)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reading the HAProxy journal: " + err.Error()})
		return
	}
	events, lines := blocklog.ParseJournal(strings.NewReader(out))
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	resp := blockedResponse{
		Period:    period,
		Since:     since.UTC(),
		Truncated: lines >= journal.BlockedLines,
		Summary:   blocklog.Summarize(events, blockedTopN),
	}
	s.addBlockedCountries(r.Context(), resp.Summary.TopIPs)
	if len(events) > limit {
		events = events[:limit]
	}
	resp.Events = nonNil(events)
	writeJSON(w, http.StatusOK, resp)
}

// addBlockedCountries looks up only the top list, under one short deadline: a
// remote GeoIP provider is billed or rate limited per lookup.
func (s *Server) addBlockedCountries(ctx context.Context, ips []blocklog.Count) {
	g := s.Eng.Settings()
	geo := s.Eng.GeoIP()
	if !g.GeoIPEnabled || geo == nil || len(ips) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for i := range ips {
		if c, _, err := geo.Lookup(ctx, g, ips[i].Key); err == nil {
			ips[i].Country = c
		}
		if ctx.Err() != nil {
			return
		}
	}
}
