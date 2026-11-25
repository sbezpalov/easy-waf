// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/audit"
	"github.com/easy-waf/easy-waf/internal/config"
)

func (s *Server) mountMCPDiagnostics(r chi.Router) {
	r.Route("/mcp/diagnostics", func(r chi.Router) {
		r.Use(s.requireMCPAPI)
		r.Get("/ready", s.handleReady)
		r.Get("/edge", s.handleEdgeStatus)
		r.Get("/applications", s.listMCPApplications)
	})
}

func (s *Server) requireMCPAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ip, ok := clientIP(r)
		if !ok || !ip.Unmap().IsLoopback() || r.TLS == nil || len(r.Header.Values(xForwardedForHdr)) != 0 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "local HTTPS required"})
			return
		}
		authorization := r.Header.Values("Authorization")
		if len(authorization) != 1 || !s.matchesMCPBearer(authorization[0]) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		sw := &statusCapture{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Record only the matched route and response status, never input or output.
		// The journal retains the access record when the database is unavailable.
		route := chi.RouteContext(r.Context()).RoutePattern()
		log.Printf("mcp diagnostics: route=%s status=%d", route, sw.code)
		if s.Eng.Store != nil {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
			defer cancel()
			ctx = audit.WithMeta(ctx, audit.Meta{User: "mcp", SourceIP: ip.String()})
			_ = s.Eng.Store.AppendAudit(ctx, "mcp.diagnostics", map[string]any{"route": route, "http_status": sw.code})
		}
	})
}

func (s *Server) matchesMCPBearer(header string) bool {
	scheme, token, found := strings.Cut(header, " ")
	return found && strings.EqualFold(scheme, "Bearer") && s.MCPAPIToken.Matches(token)
}

type mcpApplication struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PublicHost  string `json:"public_host"`
	Profile     string `json:"profile"`
	Enabled     bool   `json:"enabled"`
	Maintenance bool   `json:"maintenance"`
}

func summarizeMCPApplications(apps []config.Application) []mcpApplication {
	out := make([]mcpApplication, 0, len(apps))
	for _, a := range apps {
		out = append(out, mcpApplication{
			ID: a.ID, Name: a.Name, PublicHost: a.PublicHost, Profile: a.Profile,
			Enabled: a.Enabled, Maintenance: a.Maintenance,
		})
	}
	return out
}

func (s *Server) listMCPApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := s.Eng.Store.ListApplications(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summarizeMCPApplications(apps))
}
