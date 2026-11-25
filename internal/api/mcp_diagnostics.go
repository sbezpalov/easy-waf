// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/audit"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/store"
)

func (s *Server) mountMCPDiagnostics(r chi.Router) {
	r.Route("/mcp/diagnostics", func(r chi.Router) {
		r.Use(s.requireMCPAPI)
		r.Get("/ready", s.handleReady)
		r.Get("/edge", s.handleEdgeStatus)
		r.Get("/applications", s.listMCPApplications)
		r.Get("/application", s.describeMCPApplication)
		r.Get("/certificates", s.listMCPCertificateExpiry)
		r.Get("/revisions", s.listMCPRevisions)
		r.Get("/geoip", s.getMCPGeoIPStatus)
		r.Get("/why-blocked", s.getMCPIPBlockingEvidence)
		r.Get("/recent-events", s.listMCPRecentEvents)
	})
}

func (s *Server) listMCPRecentEvents(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recent events does not accept query parameters"})
		return
	}
	if s.Eng.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "event history unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	events, more, err := s.Eng.Store.ListRecentEdgeChanges(ctx, since, now)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Since   time.Time               `json:"since"`
		Events  []store.EdgeChangeEvent `json:"events"`
		HasMore bool                    `json:"has_more"`
	}{Since: since, Events: events, HasMore: more})
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
		out = append(out, summarizeMCPApplication(a))
	}
	return out
}

func summarizeMCPApplication(a config.Application) mcpApplication {
	return mcpApplication{
		ID: a.ID, Name: a.Name, PublicHost: a.PublicHost, Profile: a.Profile,
		Enabled: a.Enabled, Maintenance: a.Maintenance,
	}
}

func (s *Server) listMCPApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := s.Eng.Store.ListApplications(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summarizeMCPApplications(apps))
}

type mcpDiagnosticStep struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
}

func (s *Server) describeMCPApplication(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpQueryValue(r, "id")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one application id is required"})
		return
	}
	app, ok := s.loadApplication(w, r, id)
	if !ok {
		return
	}
	facts := s.collectApplicationDiagnosticFacts(r.Context(), app)
	if r.Context().Err() != nil {
		return
	}
	result := buildApplicationDiagnostics(facts)
	steps := make([]mcpDiagnosticStep, 0, len(result.Steps))
	for _, step := range result.Steps {
		steps = append(steps, mcpDiagnosticStep{ID: step.ID, Status: step.Status, Code: step.Code})
	}
	writeJSON(w, http.StatusOK, struct {
		Application mcpApplication      `json:"application"`
		CheckedAt   time.Time           `json:"checked_at"`
		Status      string              `json:"status"`
		Steps       []mcpDiagnosticStep `json:"steps"`
	}{summarizeMCPApplication(app), result.CheckedAt, result.Status, steps})
}

func mcpQueryValue(r *http.Request, key string) (string, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	values := query[key]
	if err != nil || len(query) != 1 || len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

type mcpCertificateExpiry struct {
	ID            string     `json:"id"`
	PrimaryDomain string     `json:"primary_domain"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	DaysRemaining *int       `json:"days_remaining,omitempty"`
	Status        string     `json:"status"`
}

func summarizeMCPCertificateExpiry(certs []config.Certificate, now time.Time) []mcpCertificateExpiry {
	out := make([]mcpCertificateExpiry, 0, len(certs))
	for i := range certs {
		row := certificateSummaryEntry(&certs[i], now)
		out = append(out, mcpCertificateExpiry{
			ID: row.ID, PrimaryDomain: row.PrimaryDomain, NotAfter: row.NotAfter,
			DaysRemaining: row.DaysRemaining, Status: row.Status,
		})
	}
	return out
}

func (s *Server) listMCPCertificateExpiry(w http.ResponseWriter, r *http.Request) {
	certs, err := s.Eng.Store.ListCertificates(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summarizeMCPCertificateExpiry(certs, time.Now().UTC()))
}

func (s *Server) listMCPRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := s.Eng.Store.ListConfigRevisions(r.Context(), 30)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	live, _ := s.Eng.LiveHAProxySHA256()
	type revisionSummary struct {
		ID        int64     `json:"id"`
		SHA       string    `json:"sha"`
		CreatedAt time.Time `json:"created_at"`
		IsCurrent *bool     `json:"is_current"`
	}
	out := make([]revisionSummary, 0, len(revisions))
	for _, revision := range revisions {
		var current *bool
		if live != "" {
			current = new(live == revision.HAProxySHA256)
		}
		out = append(out, revisionSummary{
			ID: revision.ID, SHA: revision.HAProxySHA256, CreatedAt: revision.At.UTC(),
			IsCurrent: current,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getMCPGeoIPStatus(w http.ResponseWriter, _ *http.Request) {
	settings := s.Eng.Settings()
	writeJSON(w, http.StatusOK, struct {
		Enabled  bool        `json:"enabled"`
		Provider string      `json:"configured_provider"`
		Cache    geoip.Stats `json:"cache"`
	}{settings.GeoIPEnabled, settings.GeoIPProvider, s.geoIPCacheStats()})
}
