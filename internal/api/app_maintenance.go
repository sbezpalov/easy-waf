// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/config"
)

type maintenanceBody struct {
	Enabled bool `json:"enabled"`
	// BypassCIDRs replaces the stored list when present.
	BypassCIDRs *[]string `json:"bypass_cidrs"`
}

// postAppMaintenance serves POST /applications/{id}/maintenance: switch one
// application's maintenance page on or off and apply.
func (s *Server) postAppMaintenance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body maintenanceBody
	if err := decodeJSONRequest(r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r, releaseMutation, ok := s.beginApplicationMutation(w, r)
	if !ok {
		return
	}
	defer releaseMutation()
	a, ok := s.loadApplication(w, r, id)
	if !ok {
		return
	}
	before, err := cloneApplication(a)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	a.Maintenance = body.Enabled
	if body.BypassCIDRs != nil {
		a.MaintenanceBypassCIDRs = *body.BypassCIDRs
	}
	if err := config.ValidateApplicationRenderSafety(&a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := s.applyOrUndo(r.Context(), "api-application-maintenance", s.restoreApplication(before)); err != nil {
		writeApplyRejected(w, err)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "app_maintenance_changed", map[string]any{
		"app_id": a.ID, "app_name": a.Name, "enabled": a.Maintenance, "bypass_cidrs": a.MaintenanceBypassCIDRs,
	})
	writeJSON(w, http.StatusOK, a)
}
