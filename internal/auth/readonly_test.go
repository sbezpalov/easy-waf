// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestReadOnlyGate(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := ReadOnlyGate(ok)
	call := func(role, method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(WithPrincipal(req.Context(), &Principal{Username: "u", Role: role}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	cases := []struct {
		role, method, path string
		want               int
	}{
		{config.RoleViewer, http.MethodGet, "/api/v1/applications", http.StatusNoContent},
		{config.RoleViewer, http.MethodGet, "/api/v1/security/blocked", http.StatusNoContent},
		{config.RoleViewer, http.MethodPost, "/api/v1/auth/confirm", http.StatusNoContent},
		{config.RoleViewer, http.MethodPost, "/api/v1/applications", http.StatusForbidden},
		{config.RoleViewer, http.MethodPost, "/api/v1/apply", http.StatusForbidden},
		{config.RoleViewer, http.MethodPatch, "/api/v1/settings", http.StatusForbidden},
		{config.RoleViewer, http.MethodDelete, "/api/v1/ipbl/local/1", http.StatusForbidden},
		{config.RoleViewer, http.MethodGet, "/api/v1/host/journal", http.StatusForbidden},
		{config.RoleViewer, http.MethodGet, "/api/v1/panel-users", http.StatusForbidden},
		{config.RoleViewer, http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		{config.RoleAdmin, http.MethodPost, "/api/v1/apply", http.StatusNoContent},
		{"", http.MethodDelete, "/api/v1/ipbl/local/1", http.StatusNoContent},
	}
	for _, c := range cases {
		if got := call(c.role, c.method, c.path); got != c.want {
			t.Errorf("%s %s %s = %d, want %d", c.role, c.method, c.path, got, c.want)
		}
	}
}
