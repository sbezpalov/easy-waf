// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

func (s *Server) listSecurityModes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, profiles.SecurityModeCatalog())
}

func (s *Server) getAppSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, ok := s.loadApplication(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.Security)
}

// appSecurityPUTRequiredKeys must all be present on PUT so omitted toggles
// cannot silently flip to false / defaults. Prefer PATCH for partial updates.
var appSecurityPUTRequiredKeys = []string{
	"rate_limit_enabled", "path_acl_enabled", "method_filter_enabled",
	"basic_waf_enabled", "bot_protection_enabled", "ip_blacklist_enabled",
	"ip_allowlist_enabled", "geoip_enabled", "crowdsec_enabled",
}

func (s *Server) putAppSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	raw, ok := readJSONBody(w, r)
	if !ok {
		return
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	for _, key := range appSecurityPUTRequiredKeys {
		if _, has := present[key]; !has {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "incomplete security body; send all toggles on PUT or use PATCH",
			})
			return
		}
	}
	var sec config.ApplicationSecurity
	if err := json.Unmarshal(raw, &sec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
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
	normalizeRequestSecurity(&sec)
	a.Security = sec
	if _, err := profiles.Resolve(a.Profile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := s.applyOrUndo(r.Context(), "api-application-security", s.restoreApplication(before)); err != nil {
		writeApplyRejected(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Security)
}

func (s *Server) patchAppSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	body, ok := readJSONBody(w, r)
	if !ok {
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
	merged, err := config.MergeApplicationSecurityJSON(a.Security, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	merged.Mode = string(profiles.DetectMode(merged))
	a.Security = merged
	if _, err := profiles.Resolve(a.Profile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := s.applyOrUndo(r.Context(), "api-application-security", s.restoreApplication(before)); err != nil {
		writeApplyRejected(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Security)
}

type securityModeBody struct {
	Mode string `json:"mode"`
}

func (s *Server) postAppSecurityMode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body securityModeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	mode, ok := profiles.ParseSecurityMode(body.Mode)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown mode"})
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
	prev := a.Security.Mode
	profiles.ApplyModePreset(&a, mode)
	if _, err := profiles.Resolve(a.Profile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := s.applyOrUndo(r.Context(), "api-application-security-mode", s.restoreApplication(before)); err != nil {
		writeApplyRejected(w, err)
		return
	}
	detail := map[string]any{
		"app_id":   a.ID,
		"app_name": a.Name,
		"from":     prev,
		"to":       a.Security.Mode,
		"toggles": map[string]bool{
			"rate_limit": a.Security.RateLimitEnabled, "path_acl": a.Security.PathACLEnabled,
			"method_filter": a.Security.MethodFilterEnabled, "basic_waf": a.Security.BasicWAFEnabled,
			"bot_protection": a.Security.BotProtectionEnabled, "ip_blacklist": a.Security.IPBlacklistEnabled,
			"ip_allowlist": a.Security.IPAllowlistEnabled, "geoip": a.Security.GeoIPEnabled,
			"crowdsec": a.Security.CrowdSecEnabled,
		},
	}
	if mode == profiles.ModeReverseProxyOnly {
		detail["level"] = "warn"
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "app_security_mode_changed", detail)
	writeJSON(w, http.StatusOK, a.Security)
}
