// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// loadApplication fetches application id for a handler. A missing row is a
// 404; any other store error is a 500 rather than a misleading "not found".
// It reports false when it has already written the response.
func (s *Server) loadApplication(w http.ResponseWriter, r *http.Request, id string) (config.Application, bool) {
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return config.Application{}, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return config.Application{}, false
	}
	return a, true
}

// normalizeRequestSecurity normalizes a security block a client sent and
// names the preset its toggles match ("custom" if none).
//
// NormalizeApplicationSecurity reads an empty mode as a legacy zero struct
// and replaces the whole block with the defaults, which silently threw away
// toggles sent without "mode". Only a block with nothing set gets defaults.
func normalizeRequestSecurity(sec *config.ApplicationSecurity) {
	if strings.TrimSpace(sec.Mode) == "" && securityHasSettings(*sec) {
		sec.Mode = string(profiles.ModeCustom)
	}
	config.NormalizeApplicationSecurity(sec)
	sec.Mode = string(profiles.DetectMode(*sec))
}

// securityHasSettings reports whether any field other than mode is set.
func securityHasSettings(sec config.ApplicationSecurity) bool {
	return sec.RateLimitEnabled || sec.PathACLEnabled || sec.MethodFilterEnabled ||
		sec.BasicWAFEnabled || sec.BotProtectionEnabled || sec.IPBlacklistEnabled ||
		sec.IPAllowlistEnabled || sec.GeoIPEnabled || sec.CrowdSecEnabled ||
		strings.TrimSpace(sec.GeoIPPolicy) != "" || len(sec.GeoIPCountryList) > 0 ||
		sec.RateLimitRPSOverride != nil || sec.RateLimitBurstOverride != nil
}

// nonNil returns s, or an empty slice when s is nil, so list endpoints answer
// [] instead of null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
