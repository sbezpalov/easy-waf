// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/easy-waf/easy-waf/internal/audit"
	"github.com/easy-waf/easy-waf/internal/auth"
)

// attachAuditRequestMeta records the current principal and client IP on the request context for AppendAudit.
// Install after auth.Session so Principal is available.
func attachAuditRequestMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := audit.Meta{}
		if p, ok := auth.PrincipalFrom(r.Context()); ok && p != nil {
			m.User = p.Username
		}
		m.SourceIP = audit.ClientHost(r)
		next.ServeHTTP(w, r.WithContext(audit.WithMeta(r.Context(), m)))
	})
}
