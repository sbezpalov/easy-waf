// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
)

func TestEnrollRejectsPasswordBcryptCannotHash(t *testing.T) {
	s := &Server{}
	body := fmt.Sprintf(`{"secret":"s3cret","username":"op","password":%q}`, strings.Repeat("a", 73))
	rec := httptest.NewRecorder()
	s.handleEnroll(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/enroll", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

// changePasswordServer creates a real operator account whose password is "old-password".
func changePasswordServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := applyFailingServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("pwtest%d", time.Now().UnixNano())
	if err := s.Eng.Store.CreateUser(context.Background(), &config.AdminUser{Username: name, PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(context.Background(), name) })
	s.JWTSecret = []byte(strings.Repeat("k", 32))
	s.LoginRL = &LoginRateLimiter{ips: map[string]*loginAttempt{}, window: 5 * time.Minute, maxInWin: 10, lockout: 15 * time.Minute}
	return s, name
}

func changePassword(s *Server, user, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.7:4000"
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{Username: user}))
	rec := httptest.NewRecorder()
	s.handleChangePassword(rec, req)
	return rec
}

func TestChangePasswordRejectsPasswordBcryptCannotHash(t *testing.T) {
	s, user := changePasswordServer(t)
	rec := changePassword(s, user, fmt.Sprintf(`{"current_password":"old-password","new_password":%q}`, strings.Repeat("b", 73)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePasswordSuccessResetsLimiter(t *testing.T) {
	s, user := changePasswordServer(t)
	for i := 0; i < 8; i++ {
		s.LoginRL.Allow("192.0.2.7")
	}
	rec := changePassword(s, user, `{"current_password":"old-password","new_password":"new-password-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if _, tracked := s.LoginRL.ips["192.0.2.7"]; tracked {
		t.Fatal("a successful password change left its attempts counted")
	}
}
