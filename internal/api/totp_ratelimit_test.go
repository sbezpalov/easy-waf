// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPEnableLocksOutBeforeTouchingTheUser(t *testing.T) {
	s := &Server{LoginRL: &LoginRateLimiter{
		ips:      map[string]*loginAttempt{},
		window:   time.Minute,
		maxInWin: 1,
		lockout:  time.Minute,
	}}
	if allowed, _ := s.LoginRL.Allow("192.0.2.8"); !allowed {
		t.Fatal("primer attempt should be allowed")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/enable", strings.NewReader(`{"code":"000000"}`))
	req.RemoteAddr = "192.0.2.8:9"
	rec := httptest.NewRecorder()
	s.totpEnable(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}
