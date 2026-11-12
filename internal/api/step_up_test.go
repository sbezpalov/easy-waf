// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
)

// Diagnostics only send probes and stay outside RequireStepUp.
var hostRoutesWithoutStepUp = map[string]bool{
	"POST /host/diagnostics/ping":  true,
	"POST /host/diagnostics/trace": true,
}

func TestEveryMutatingHostRouteRequiresStepUp(t *testing.T) {
	r := chi.NewRouter()
	(&Server{}).mountHostRoutes(r)
	param := regexp.MustCompile(`\{[^}]+\}`)
	checked := 0

	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if method == http.MethodGet || hostRoutesWithoutStepUp[method+" "+route] {
			return nil
		}
		checked++
		req := httptest.NewRequest(method, param.ReplaceAllString(route, "x"), nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
			Username: "op",
			Role:     config.RoleAdmin,
		}))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s: status %d: %s", method, route, rec.Code, rec.Body.String())
		}
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
	if checked < 15 {
		t.Fatalf("walked only %d routes", checked)
	}
}

func TestManagementTLSRequiresStepUp(t *testing.T) {
	assertStepUpRequired(t, http.MethodPut, "/api/v1/settings/management-tls", `{}`)
}

func TestTrustBoundaryWritesRequireStepUp(t *testing.T) {
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPut, "/api/v1/settings", `{}`},
		{http.MethodPatch, "/api/v1/settings", `{}`},
		{http.MethodPost, "/api/v1/apply", `{"label":"x"}`},
		{http.MethodPost, "/api/v1/revisions/1/rollback", ``},
		{http.MethodPost, "/api/v1/diagnostics/bundle", ``},
		{http.MethodPut, "/api/v1/applications/app1/security", `{}`},
		{http.MethodPost, "/api/v1/ipbl/sync", ``},
		{http.MethodPost, "/api/v1/integrations/crowdsec/decisions", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			assertStepUpRequired(t, tc.method, tc.path, tc.body)
		})
	}
}

func assertStepUpRequired(t *testing.T, method, path, body string) {
	t.Helper()
	s, user := changePasswordServer(t)
	tok, err := auth.SignJWT(s.JWTSecret, user, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.168.1.10:4000"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()

	s.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func confirmPassword(s *Server, p *auth.Principal, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/confirm", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.8:4000"
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	s.handleConfirmPassword(rec, req)
	return rec
}

func TestConfirmPasswordIssuesTokenWithStepUp(t *testing.T) {
	s, user := changePasswordServer(t)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	rec := confirmPassword(s, &auth.Principal{Username: user, ExpiresAt: expires}, `{"password":"old-password"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got confirmResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseJWT(s.JWTSecret, got.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.StepUpAt == 0 {
		t.Fatal("token carries no step-up time")
	}
	if !claims.ExpiresAt.Equal(expires) {
		t.Fatalf("expires %v, want %v", claims.ExpiresAt.Time, expires)
	}
	if got.StepUpExpiresInSeconds != int64(stepUpWindow.Seconds()) {
		t.Fatalf("window %d", got.StepUpExpiresInSeconds)
	}
}

func TestConfirmPasswordRejectsWrongPassword(t *testing.T) {
	s, user := changePasswordServer(t)

	rec := confirmPassword(s, &auth.Principal{Username: user, ExpiresAt: time.Now().Add(time.Hour)}, `{"password":"wrong"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestConfirmPasswordIsRateLimited(t *testing.T) {
	s, user := changePasswordServer(t)
	s.LoginRL.maxInWin = 2
	p := &auth.Principal{Username: user, ExpiresAt: time.Now().Add(time.Hour)}

	var last *httptest.ResponseRecorder
	for range 3 {
		last = confirmPassword(s, p, `{"password":"wrong"}`)
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d: an unthrottled confirm is a password oracle for a stolen session", last.Code)
	}
}

func TestConfirmPasswordRefusesAutomationToken(t *testing.T) {
	s := &Server{}

	rec := confirmPassword(s, &auth.Principal{Username: "automation", IsLegacyToken: true}, `{"password":"x"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}
