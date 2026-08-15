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

func TestLimitRequestBody(t *testing.T) {
	h := limitRequestBody(4)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected size error")
		}
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", rec.Code)
	}
}
