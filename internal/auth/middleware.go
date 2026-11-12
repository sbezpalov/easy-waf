// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

var legacyTokenWarn sync.Once

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
				legacyTokenWarn.Do(func() {
					log.Printf("auth: EASY_WAF_ADMIN_TOKEN accepted; prefer a session JWT — trust-boundary writes require step-up, which this static token cannot provide")
				})
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
// password within window. The legacy EASY_WAF_ADMIN_TOKEN does not bypass this:
// it has no password to confirm, so it cannot perform trust-boundary writes.
func RequireStepUp(window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if time.Since(p.StepUpAt) > window {
				jsonErr(w, http.StatusForbidden, "step_up_required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin allows only RoleAdmin and the legacy automation principal.
// Unknown or empty roles fail closed (unlike ReadOnlyGate, which only blocks
// an exact viewer role).
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if p.IsLegacyToken || p.Role == config.RoleAdmin {
			next.ServeHTTP(w, r)
			return
		}
		jsonErr(w, http.StatusForbidden, "forbidden")
	})
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
	"/api/v1/auth/totp/setup":      true,
	"/api/v1/auth/totp/enable":     true,
	"/api/v1/auth/totp/disable":    true,
}

// viewerDeniedPrefixes stay closed to viewers even for reads: host
// management, support bundles, the panel user list and audit (host rollback
// tokens used to appear in audit detail).
var viewerDeniedPrefixes = []string{"/api/v1/host/", "/api/v1/diagnostics/", "/api/v1/panel-users", "/api/v1/audit"}

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
