// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

// haproxyStats returns the stats collector, creating one on first use when
// the server was built without it. Concurrent requests used to race on that
// lazy assignment.
func (s *Server) haproxyStats() *metrics.HAProxyCollector {
	s.statsOnce.Do(func() {
		if s.HAProxyMetrics == nil {
			s.HAProxyMetrics = metrics.NewHAProxyCollector()
		}
	})
	return s.HAProxyMetrics
}

func (s *Server) handleStatsHAProxy(w http.ResponseWriter, r *http.Request) {
	path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
	rep, _ := s.haproxyStats().FetchContext(r.Context(), path)
	if rep == nil {
		return // client went away
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
	rep, _ := s.haproxyStats().FetchContext(r.Context(), path)
	if rep == nil {
		return // client went away
	}
	sum := metrics.BuildSummary(rep)
	writeJSON(w, http.StatusOK, sum)
}
