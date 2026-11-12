// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stepUpStatus(t *testing.T, p *Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/power/reboot", nil)
	if p != nil {
		req = req.WithContext(WithPrincipal(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	RequireStepUp(5*time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	return rec
}

func TestRequireStepUp(t *testing.T) {
	for name, tc := range map[string]struct {
		principal *Principal
		want      int
	}{
		"never confirmed":     {&Principal{Username: "op"}, http.StatusForbidden},
		"confirmed just now":  {&Principal{Username: "op", StepUpAt: time.Now()}, http.StatusNoContent},
		"confirmation lapsed": {&Principal{Username: "op", StepUpAt: time.Now().Add(-6 * time.Minute)}, http.StatusForbidden},
		"automation token":    {&Principal{Username: "automation", IsLegacyToken: true}, http.StatusForbidden},
		"no principal":        {nil, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			rec := stepUpStatus(t, tc.principal)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestRequireStepUpNamesTheErrorForClients(t *testing.T) {
	rec := stepUpStatus(t, &Principal{Username: "op"})

	if !strings.Contains(rec.Body.String(), `"error":"step_up_required"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestStepUpJWTKeepsTheSessionExpiry(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	expires := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	confirmed := time.Now().Truncate(time.Second)

	tok, err := SignStepUpJWT(secret, "op", 3, expires, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(secret, tok)

	if err != nil {
		t.Fatal(err)
	}
	if !claims.ExpiresAt.Equal(expires) {
		t.Fatalf("expires %v, want %v: confirming must not extend a session", claims.ExpiresAt.Time, expires)
	}
	if claims.StepUpAt != confirmed.Unix() || claims.SessionVersion != 3 || claims.Subject != "op" {
		t.Fatalf("claims %+v", claims)
	}
}

func TestOrdinarySessionCarriesNoStepUp(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))

	tok, err := SignJWT(secret, "op", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(secret, tok)

	if err != nil {
		t.Fatal(err)
	}
	if !claims.stepUpTime().IsZero() {
		t.Fatalf("step-up %v", claims.stepUpTime())
	}
}
