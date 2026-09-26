// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestHealthReadyWithoutDatabaseIs503(t *testing.T) {
	// A remote peer outside management_allowed_cidrs: readiness, like /health,
	// is for probes and must not need the ACL.
	s := &Server{Eng: engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}}), JWTSecret: []byte("test-secret")}
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/health", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	rec = httptest.NewRecorder()
	s.Router().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("/health: %d", rec.Code)
	}
}
