// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestSessionRejectsStaleJWTAfterPasswordChange(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	user := "ew-test-jwt-" + time.Now().UTC().Format("150405.000")
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	u := &config.AdminUser{Username: user, PasswordHash: string(hash), SessionVersion: 1}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteUserByUsername(ctx, user) })

	secret := []byte("0123456789abcdef")
	oldTok, err := auth.SignJWT(secret, user, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := auth.Session(st, secret)(ok)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+oldTok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("fresh token before password change: %d", rr.Code)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("new-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserPassword(ctx, u.ID, string(newHash), false); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req2.Header.Set("Authorization", "Bearer "+oldTok)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("old token after password change: %d", rr2.Code)
	}

	got, err := st.GetUserByUsername(ctx, user)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	newTok, err := auth.SignJWT(secret, user, got.SessionVersion, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req3.Header.Set("Authorization", "Bearer "+newTok)
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusNoContent {
		t.Fatalf("new token: %d", rr3.Code)
	}

	const legacyToken = "legacy-automation-token-01234"
	t.Setenv("EASY_WAF_ADMIN_TOKEN", legacyToken)
	hLegacy := auth.Session(st, secret)(ok)
	reqL := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	reqL.Header.Set("Authorization", "Bearer "+legacyToken)
	rrL := httptest.NewRecorder()
	hLegacy.ServeHTTP(rrL, reqL)
	if rrL.Code != http.StatusNoContent {
		t.Fatalf("legacy token: %d", rrL.Code)
	}
}
