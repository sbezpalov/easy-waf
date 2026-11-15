// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
)

func TestLoginRateLimitCoversUnparseableRemoteAddr(t *testing.T) {
	s := applyFailingServer(t)
	s.LoginRL = &LoginRateLimiter{
		ips:      map[string]*loginAttempt{},
		window:   time.Minute,
		maxInWin: 1,
		lockout:  time.Minute,
	}
	body := `{"username":"nobody","password":"secretsecret"}`
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		req.RemoteAddr = "not-an-address"
		rec := httptest.NewRecorder()
		s.handleLogin(rec, req)
		return rec
	}
	first := call()
	if first.Code == http.StatusTooManyRequests {
		t.Fatalf("first attempt was limited: %s", first.Body.String())
	}
	second := call()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("unparseable RemoteAddr bypassed the limiter: %d %s", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestSettingsWriteHidesStoreErrors(t *testing.T) {
	s := applyFailingServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/settings", strings.NewReader(`{"acme_email":"ops@example.test"}`))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	s.patchSettings(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "context canceled") || strings.Contains(strings.ToLower(rec.Body.String()), "postgres") {
		t.Fatalf("store error reached the client: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "internal error") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestRouterAuthzValidationAndLimits(t *testing.T) {
	s := applyFailingServer(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	s.JWTSecret = secret
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "-")
	adminName := "adm-" + suffix
	viewerName := "view-" + suffix
	hash, err := bcrypt.GenerateFromPassword([]byte("pw-123456789"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		name string
		role string
	}{
		{adminName, config.RoleAdmin},
		{viewerName, config.RoleViewer},
	} {
		if err := s.Eng.Store.CreateUser(ctx, &config.AdminUser{Username: user.name, PasswordHash: string(hash), Role: user.role}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(context.Background(), user.name) })
	}
	adminUser, err := s.Eng.Store.GetUserByUsername(ctx, adminName)
	if err != nil || adminUser == nil {
		t.Fatal(err)
	}
	viewerUser, err := s.Eng.Store.GetUserByUsername(ctx, viewerName)
	if err != nil || viewerUser == nil {
		t.Fatal(err)
	}
	adminTok, err := auth.SignJWT(secret, adminUser.Username, adminUser.SessionVersion, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	viewerTok, err := auth.SignJWT(secret, viewerUser.Username, viewerUser.SessionVersion, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stepTok, err := auth.SignStepUpJWT(secret, adminUser.Username, adminUser.SessionVersion, time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := s.Router()

	call := func(method, path, token, body string, extra func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "10.1.2.3:9"
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if extra != nil {
			extra(req)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(http.MethodGet, "/health", "", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("health: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/api/v1/applications", "", `{}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous write: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/auth/login", "", `{"username":"x","password":"y"}`, func(r *http.Request) {
		r.Header.Del("X-Requested-With")
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/applications", viewerTok, `{}`, nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "read_only") {
		t.Fatalf("viewer write: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/v1/host/journal", viewerTok, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer host read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/apply", adminTok, `{}`, nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Fatalf("admin without step-up: %d %s", rec.Code, rec.Body.String())
	}
	badApp := `{"name":"bad","public_host":"NOT A HOST","backend_host":"10.0.0.5","backend_port":80,"profile":"balanced","listen_mode":"http_only"}`
	if rec := call(http.MethodPost, "/api/v1/applications", stepTok, badApp, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid application: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/applications", stepTok, `{`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("broken JSON: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPatch, "/api/v1/settings", stepTok, `{"management_allowed_cidrs":["not-a-cidr"]}`, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "management_allowed_cidrs") {
		t.Fatalf("invalid CIDR: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/auth/login", "", "", func(r *http.Request) {
		r.ContentLength = maxAPIRequestBodyBytes + 1
	}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/v1/applications", viewerTok, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("viewer read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/v1/applications/missing-app", adminTok, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing application: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/auth/login", "", `{"username":"nobody","password":"secretsecret"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/auth/enroll", "", `{"secret":"x","username":"ops","password":"short"}`, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "8 characters") {
		t.Fatalf("short enroll password: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/ipbl/local", stepTok, `{"cidr":"999.1.1.1"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid blocklist entry: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/v1/certificates/no-such-cert/request-issue", stepTok, `{"mode":"ftp"}`, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing certificate: %d %s", rec.Code, rec.Body.String())
	}
}
