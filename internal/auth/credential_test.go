// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/auth"
)

func TestSessionAcceptsBearerSchemeCaseInsensitively(t *testing.T) {
	const legacy = "legacy-automation-token-01234"
	t.Setenv("EASY_WAF_ADMIN_TOKEN", legacy)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Legacy tokens are checked before any database lookup, so a nil store is enough.
	h := auth.Session(nil, []byte("0123456789abcdef0123456789abcdef"))(ok)

	for _, header := range []string{"bearer " + legacy, "BEARER " + legacy, "Bearer " + legacy, legacy} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
		req.Header.Set("Authorization", header)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("Authorization %q: got %d, want 204", header, rr.Code)
		}
	}
}
