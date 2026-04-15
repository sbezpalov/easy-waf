package api

import (
	"net/http"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

func (s *Server) handleStatsHAProxy(w http.ResponseWriter, r *http.Request) {
	if s.HAProxyMetrics == nil {
		s.HAProxyMetrics = metrics.NewHAProxyCollector()
	}
	path := metrics.StatsSocketPath(s.Eng.Settings, s.Eng.StateDir)
	rep, _ := s.HAProxyMetrics.Fetch(path)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	if s.HAProxyMetrics == nil {
		s.HAProxyMetrics = metrics.NewHAProxyCollector()
	}
	path := metrics.StatsSocketPath(s.Eng.Settings, s.Eng.StateDir)
	rep, _ := s.HAProxyMetrics.Fetch(path)
	sum := metrics.BuildSummary(rep)
	writeJSON(w, http.StatusOK, sum)
}
