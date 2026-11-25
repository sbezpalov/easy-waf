// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	database := s.databaseReadiness(r.Context())
	if database != "ok" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": database})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": database})
}

func (s *Server) databaseReadiness(parent context.Context) string {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if s.Eng == nil || s.Eng.Store == nil {
		return "not configured"
	}
	if err := s.Eng.Store.Ping(ctx); err != nil {
		// No error detail: this endpoint is exempt from auth and the ACL.
		return "unreachable"
	}
	return "ok"
}
