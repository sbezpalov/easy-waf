// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestRequireAdmin(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireAdmin(ok)
	call := func(p *Principal) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/panel-users", nil)
		if p != nil {
			req = req.WithContext(WithPrincipal(req.Context(), p))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(nil); got != http.StatusUnauthorized {
		t.Fatalf("no principal: %d", got)
	}
	if got := call(&Principal{Username: "v", Role: config.RoleViewer}); got != http.StatusForbidden {
		t.Fatalf("viewer: %d", got)
	}
	if got := call(&Principal{Username: "x", Role: ""}); got != http.StatusForbidden {
		t.Fatalf("empty role must fail closed: %d", got)
	}
	if got := call(&Principal{Username: "a", Role: config.RoleAdmin}); got != http.StatusNoContent {
		t.Fatalf("admin: %d", got)
	}
	if got := call(&Principal{Username: "automation", IsLegacyToken: true, Role: config.RoleAdmin}); got != http.StatusNoContent {
		t.Fatalf("legacy: %d", got)
	}
}
