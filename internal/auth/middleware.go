// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

// Session validates Authorization: Bearer — JWT (HS256) or legacy EASY_WAF_ADMIN_TOKEN.
// On success, attaches Principal to the request context.
func Session(st *store.Store, jwtSecret []byte) func(http.Handler) http.Handler {
	legacy := loadLegacyToken()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			raw = strings.TrimSpace(raw)
			if raw == "" {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if legacy.Matches(raw) {
				p := &Principal{Username: "automation", IsLegacyToken: true, Role: config.RoleAdmin}
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}
			claims, err := ParseJWT(jwtSecret, raw)
			if err != nil {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			u, err := st.GetUserByUsername(r.Context(), claims.Subject)
			if err != nil || u == nil {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !SessionMatches(claims.SessionVersion, u.SessionVersion) {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			p := &Principal{
				Username:           u.Username,
				MustChangePassword: u.MustChangePassword,
				Role:               u.Role,
				ExpiresAt:          claims.ExpiresAt.Time,
				StepUpAt:           claims.stepUpTime(),
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RequireStepUp returns 403 step_up_required unless the session confirmed its
// password within window. The automation token passes: it is a root-only secret
// from easy-waf.env, and no person is there to confirm anything.
func RequireStepUp(window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !p.IsLegacyToken && time.Since(p.StepUpAt) > window {
				jsonErr(w, http.StatusForbidden, "step_up_required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// PasswordChangeGate returns 403 until the user changes the initial password (not applied to legacy tokens).
func PasswordChangeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if p.IsLegacyToken || !p.MustChangePassword {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if path == "/api/v1/auth/me" || path == "/api/v1/auth/change-password" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"password_change_required","must_change_password":true}` + "\n"))
	})
}

// viewerAllowedPOST are the writes a viewer may make: its own session and password.
var viewerAllowedPOST = map[string]bool{
	"/api/v1/auth/logout":          true,
	"/api/v1/auth/change-password": true,
	"/api/v1/auth/confirm":         true,
}

// viewerDeniedPrefixes stay closed to viewers even for reads: host
// management, support bundles and the panel user list.
var viewerDeniedPrefixes = []string{"/api/v1/host/", "/api/v1/diagnostics/", "/api/v1/panel-users"}

// ReadOnlyGate returns 403 read_only for a viewer's writes and for the areas
// in viewerDeniedPrefixes. Admins and the automation token pass.
func ReadOnlyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok || p.Role != config.RoleViewer {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		for _, pre := range viewerDeniedPrefixes {
			if strings.HasPrefix(path, pre) {
				jsonErr(w, http.StatusForbidden, "read_only")
				return
			}
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || (r.Method == http.MethodPost && viewerAllowedPOST[path]) {
			next.ServeHTTP(w, r)
			return
		}
		jsonErr(w, http.StatusForbidden, "read_only")
	})
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}` + "\n"))
}
