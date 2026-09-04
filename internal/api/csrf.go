// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
)

// RequireXHR rejects state-changing requests (POST/PUT/PATCH/DELETE) that lack
// the X-Requested-With header. This is a defense-in-depth measure against CSRF
// in environments where JWT Bearer is the only auth mechanism (no cookies).
//
// GET, HEAD, OPTIONS and /health are exempt.
func RequireXHR(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		xhr := strings.TrimSpace(r.Header.Get("X-Requested-With"))
		if !strings.EqualFold(xhr, "XMLHttpRequest") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"missing X-Requested-With header"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
