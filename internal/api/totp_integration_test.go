// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestLoginWithTOTP(t *testing.T) {
	s := applyFailingServer(t)
	s.JWTSecret = []byte("0123456789abcdef0123456789abcdef")
	s.LoginRL = nil
	ctx := context.Background()
	name := fmt.Sprintf("totp%d", time.Now().UnixNano())
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw-123456789"), bcrypt.MinCost)
	if err := s.Eng.Store.CreateUser(ctx, &config.AdminUser{Username: name, PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(ctx, name) })
	secret, _ := auth.NewTOTPSecret()
	if err := s.Eng.Store.SetTOTPPending(ctx, name, secret); err != nil {
		t.Fatal(err)
	}
	codes, _ := auth.GenerateRecoveryCodes(2)
	if err := s.Eng.Store.EnableTOTP(ctx, name, secret, 0, []string{auth.HashRecoveryCode(codes[0]), auth.HashRecoveryCode(codes[1])}); err != nil {
		t.Fatal(err)
	}
	login := func(code string) (int, string) {
		b, _ := json.Marshal(map[string]string{"username": name, "password": "pw-123456789", "totp_code": code})
		rec := httptest.NewRecorder()
		s.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b)))
		return rec.Code, rec.Body.String()
	}
	if c, b := login(""); c != http.StatusUnauthorized || !strings.Contains(b, "totp_required") {
		t.Fatalf("no code: %d %s", c, b)
	}
	if c, _ := login("abcd-efgh-ijkl-mnop"); c != http.StatusUnauthorized {
		t.Fatalf("bad recovery code: %d", c)
	}
	code, _ := auth.TOTPCode(secret, time.Now())
	if c, b := login(code); c != http.StatusOK {
		t.Fatalf("valid code: %d %s", c, b)
	}
	if c, _ := login(code); c != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d", c)
	}
	if c, _ := login(strings.ToUpper(codes[0])); c != http.StatusOK {
		t.Fatalf("recovery code: %d", c)
	}
	if c, _ := login(codes[0]); c != http.StatusUnauthorized {
		t.Fatalf("reused recovery code: %d", c)
	}
	if err := s.Eng.Store.DisableTOTP(ctx, name); err != nil {
		t.Fatal(err)
	}
	if c, _ := login(""); c != http.StatusOK {
		t.Fatalf("after disable: %d", c)
	}
}
