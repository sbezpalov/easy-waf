// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

func (s *Server) handleStatsHAProxy(w http.ResponseWriter, r *http.Request) {
	if s.HAProxyMetrics == nil {
		s.HAProxyMetrics = metrics.NewHAProxyCollector()
	}
	path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
	rep, _ := s.HAProxyMetrics.FetchContext(r.Context(), path)
	if rep == nil {
		return // client went away
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	if s.HAProxyMetrics == nil {
		s.HAProxyMetrics = metrics.NewHAProxyCollector()
	}
	path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
	rep, _ := s.HAProxyMetrics.FetchContext(r.Context(), path)
	if rep == nil {
		return // client went away
	}
	sum := metrics.BuildSummary(rep)
	writeJSON(w, http.StatusOK, sum)
}
