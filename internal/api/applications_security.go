package api

import (
	"encoding/json"
	"io"
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
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, a.Security)
}

func (s *Server) putAppSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var sec config.ApplicationSecurity
	if err := json.NewDecoder(r.Body).Decode(&sec); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	config.NormalizeApplicationSecurity(&sec)
	sec.Mode = string(profiles.DetectMode(sec))
	a.Security = sec
	if _, err := profiles.Resolve(a.Profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.maybeAutoApply(r.Context(), "api-application-security"); err != nil {
		http.Error(w, "security saved but edge apply failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, a.Security)
}

func (s *Server) patchAppSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	merged, err := config.MergeApplicationSecurityJSON(a.Security, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	merged.Mode = string(profiles.DetectMode(merged))
	a.Security = merged
	if _, err := profiles.Resolve(a.Profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.maybeAutoApply(r.Context(), "api-application-security"); err != nil {
		http.Error(w, "security saved but edge apply failed: "+err.Error(), http.StatusBadGateway)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mode, ok := profiles.ParseSecurityMode(body.Mode)
	if !ok {
		http.Error(w, "unknown mode", http.StatusBadRequest)
		return
	}
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	prev := a.Security.Mode
	profiles.ApplyModePreset(&a, mode)
	if _, err := profiles.Resolve(a.Profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.maybeAutoApply(r.Context(), "api-application-security-mode"); err != nil {
		http.Error(w, "security mode saved but edge apply failed: "+err.Error(), http.StatusBadGateway)
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
