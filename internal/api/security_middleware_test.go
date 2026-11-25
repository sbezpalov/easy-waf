// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)

	for _, header := range []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-Permitted-Cross-Domain-Policies",
	} {
		if rec.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}

	// Test HSTS on HTTPS forwarded header
	recHTTPS := httptest.NewRecorder()
	reqHTTPS := httptest.NewRequest(http.MethodGet, "/", nil)
	reqHTTPS.Header.Set("X-Forwarded-Proto", "https")
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recHTTPS, reqHTTPS)
	if hsts := recHTTPS.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Fatalf("expected Strict-Transport-Security header on HTTPS request")
	}
}

func TestManagementResponsePrivacy(t *testing.T) {
	for _, tc := range []struct{ path, cache string }{
		{"/api/v1/settings", "no-store"},
		{"/api/v1/auth/totp/setup", "no-store"},
		{"/api/v1/integrations/mcp/approve", "no-store"},
		{"/", ""},
	} {
		rec := httptest.NewRecorder()
		securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if got := rec.Header().Get("Cache-Control"); got != tc.cache {
			t.Errorf("%s cache policy = %q, want %q", tc.path, got, tc.cache)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s referrer policy = %q", tc.path, got)
		}
	}
}

func TestLimitRequestBody(t *testing.T) {
	h := limitRequestBody(4)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected size error")
		}
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	req.ContentLength = -1
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", rec.Code)
	}
}
