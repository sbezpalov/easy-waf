// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"time"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

type mcpHAProxyFrontends struct {
	Open    int `json:"open"`
	Full    int `json:"full"`
	Stopped int `json:"stopped"`
	Unknown int `json:"unknown"`
}

type mcpHAProxyBackends struct {
	Healthy  int `json:"healthy"`
	Degraded int `json:"degraded"`
	Down     int `json:"down"`
	Unknown  int `json:"unknown"`
}

type mcpHAProxyCheck struct {
	State       string               `json:"state"`
	CollectedAt *time.Time           `json:"collected_at,omitempty"`
	Frontends   *mcpHAProxyFrontends `json:"frontends,omitempty"`
	Backends    *mcpHAProxyBackends  `json:"backends,omitempty"`
}

func (s *Server) checkMCPHAProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "HAProxy check does not accept query parameters"})
		return
	}
	path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
	report, err := s.haproxyStats().FetchContext(r.Context(), path)
	if err != nil {
		report = nil
	}
	writeJSON(w, http.StatusOK, summarizeMCPHAProxy(report))
}

func summarizeMCPHAProxy(report *metrics.HAProxyReport) mcpHAProxyCheck {
	if report == nil || report.Error != "" || report.CollectedAt.IsZero() {
		return mcpHAProxyCheck{State: "unavailable"}
	}
	frontends := new(mcpHAProxyFrontends)
	for _, frontend := range report.Frontends {
		switch frontend.Status {
		case "OPEN":
			frontends.Open++
		case "FULL":
			frontends.Full++
		case "STOP":
			frontends.Stopped++
		default:
			frontends.Unknown++
		}
	}
	backends := new(mcpHAProxyBackends)
	for _, backend := range report.Backends {
		switch backend.Health {
		case "healthy":
			backends.Healthy++
		case "degraded":
			backends.Degraded++
		case "down":
			backends.Down++
		default:
			backends.Unknown++
		}
	}
	return mcpHAProxyCheck{State: "available", CollectedAt: &report.CollectedAt, Frontends: frontends, Backends: backends}
}
