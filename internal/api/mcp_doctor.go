// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

type mcpDoctorReport struct {
	Database string          `json:"database"`
	Edge     string          `json:"edge_configuration"`
	HAProxy  mcpHAProxyCheck `json:"haproxy"`
}

func (s *Server) handleMCPDoctor(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "doctor does not accept query parameters"})
		return
	}
	report := mcpDoctorReport{Database: s.databaseReadiness(r.Context()), Edge: "unavailable"}
	if report.Database == "ok" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		edge, err := s.edgeStatus(ctx)
		cancel()
		if err == nil {
			report.Edge = mcpDoctorEdgeState(edge)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	report.HAProxy = s.mcpHAProxyRuntime(ctx)
	writeJSON(w, http.StatusOK, report)
}

func mcpDoctorEdgeState(edge config.EdgeStatus) string {
	switch {
	case edge.LastApply != nil && edge.LastApply.Outcome == config.EdgeApplyOutcomeFailed:
		return "apply_failed"
	case edge.Pending == nil:
		return "apply_unconfirmed"
	case *edge.Pending:
		return "changes_pending"
	case edge.Runtime.State != config.EdgeRuntimeKnown:
		return "artifact_unavailable"
	case edge.LastApply == nil || edge.LastApply.Outcome != config.EdgeApplyOutcomeSuccess || edge.LastApply.RevisionSHA == "":
		return "artifact_unconfirmed"
	case edge.LastApply.RevisionSHA != edge.Runtime.RevisionSHA:
		return "artifact_differs"
	default:
		return "applied"
	}
}
