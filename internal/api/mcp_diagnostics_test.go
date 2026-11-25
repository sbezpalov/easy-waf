// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestMCPDiagnosticsBoundary(t *testing.T) {
	const path = "/api/v1/mcp/diagnostics/ready"
	const applicationPath = "https://localhost/api/v1/mcp/diagnostics/application"
	const ipPath = "https://localhost/api/v1/mcp/diagnostics/why-blocked"
	const eventsPath = "https://localhost/api/v1/mcp/diagnostics/recent-events"
	secret := strings.Repeat("m", 40)
	t.Setenv("EASY_WAF_MCP_API_TOKEN", secret)
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8", "::1/128", "192.0.2.0/24"}})
	server := &Server{Eng: eng, JWTSecret: []byte("test-only"), MCPAPIToken: auth.LoadMCPAPIToken(nil)}
	bearer := "Bearer " + secret
	for _, tc := range []struct {
		name, method, url, peer, header, forwarded string
		want                                       int
	}{
		{"missing", "GET", "https://localhost" + path, "127.0.0.1:31000", "", "", http.StatusUnauthorized},
		{"wrong", "GET", "https://localhost" + path, "127.0.0.1:31000", "Bearer wrong", "", http.StatusUnauthorized},
		{"bare", "GET", "https://localhost" + path, "127.0.0.1:31000", secret, "", http.StatusUnauthorized},
		{"ipv4", "GET", "https://localhost" + path, "127.0.0.1:31000", bearer, "", http.StatusServiceUnavailable},
		{"ipv6", "GET", "https://localhost" + path, "[::1]:31000", bearer, "", http.StatusServiceUnavailable},
		{"http", "GET", "http://localhost" + path, "127.0.0.1:31000", bearer, "", http.StatusForbidden},
		{"management LAN", "GET", "https://localhost" + path, "192.0.2.1:31000", bearer, "", http.StatusForbidden},
		{"forwarded loopback", "GET", "https://localhost" + path, "127.0.0.1:31000", bearer, "127.0.0.1", http.StatusForbidden},
		{"post", "POST", "https://localhost" + path, "127.0.0.1:31000", bearer, "", http.StatusMethodNotAllowed},
		{"panel API", "GET", "https://localhost/api/v1/settings", "127.0.0.1:31000", bearer, "", http.StatusUnauthorized},
		{"apply", "POST", "https://localhost/api/v1/apply", "127.0.0.1:31000", bearer, "", http.StatusUnauthorized},
		{"missing application ID", "GET", applicationPath, "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"duplicate application ID", "GET", applicationPath + "?id=one&id=two", "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"missing IP", "GET", ipPath, "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"duplicate IP", "GET", ipPath + "?ip=192.0.2.17&ip=192.0.2.18", "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"CIDR", "GET", ipPath + "?ip=192.0.2.0/24", "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"scoped IP", "GET", ipPath + "?ip=fe80::42%25eth0", "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"events filter", "GET", eventsPath + "?limit=100", "127.0.0.1:31000", bearer, "", http.StatusBadRequest},
		{"events no database", "GET", eventsPath, "127.0.0.1:31000", bearer, "", http.StatusServiceUnavailable},
		{"events no bearer", "GET", eventsPath, "127.0.0.1:31000", "", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.url, nil)
			r.RemoteAddr = tc.peer
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tc.want, w.Body)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "https://localhost"+path, nil)
	r.RemoteAddr = "127.0.0.1:31000"
	r.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	(&Server{Eng: eng}).Router().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured diagnostics status = %d, want 404", w.Code)
	}
}

func TestMCPDiagnosticsWithPostgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secret := strings.Repeat("m", 40)
	t.Setenv("EASY_WAF_MCP_API_TOKEN", secret)
	app := config.Application{
		Name: "MCP diagnostic fixture", PublicHost: "127.0.0.42", Profile: "balanced", Enabled: true,
		BackendHost: "backend.example.test", BackendPort: 8080, ListenMode: "http_only",
	}
	if err := st.UpsertApplication(t.Context(), &app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := st.DeleteApplication(ctx, app.ID); err != nil {
			t.Error(err)
		}
	})
	s := &Server{Eng: engine.New(t.TempDir(), st, config.GlobalSettings{}), MCPAPIToken: auth.LoadMCPAPIToken(nil)}
	router := s.Router()
	start := time.Now().Add(-time.Second)
	routes := []struct{ suffix, want string }{
		{"/ready", `"database":"ok"`}, {"/edge", `"saved_generation"`}, {"/applications", "["},
		{"/certificates", "["}, {"/revisions", "["}, {"/geoip", `"configured_provider"`},
		{"/application?id=" + url.QueryEscape(app.ID), `"code":"hostname_resolved"`},
		{"/recent-events", `"events":[`},
	}
	for _, route := range routes {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/mcp/diagnostics"+route.suffix, nil)
		r.RemoteAddr = "127.0.0.1:31000"
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), route.want) {
			t.Fatalf("%s: unexpected response %d: %s", route.suffix, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), `"evidence"`) || strings.Contains(w.Body.String(), app.BackendHost) {
			t.Fatalf("%s exposed internal diagnostics fields: %s", route.suffix, w.Body)
		}
	}
	rows, _, err := st.ListAuditLogs(t.Context(), store.AuditListParams{Limit: len(routes), From: &start, Action: "mcp.diagnostics"})
	if err != nil || len(rows) != len(routes) {
		t.Fatalf("expected %d MCP audit records, got %d: %v", len(routes), len(rows), err)
	}
	for i := range routes {
		suffix, _, _ := strings.Cut(routes[len(routes)-1-i].suffix, "?")
		entry := rows[i]
		if entry.UserName != "mcp" || !strings.Contains(string(entry.Details), `"/api/v1/mcp/diagnostics`+suffix+`"`) || strings.Contains(string(entry.Details), app.ID) {
			t.Fatalf("unexpected MCP audit record: %+v", entry)
		}
	}
}

func TestMCPIPDiagnosticsWithPostgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	const ip, cidr, note = "2001:db8:5aaa:ea::42", "2001:db8:5aaa:ea::/64", "fixture note"
	secret := strings.Repeat("m", 40)
	t.Setenv("EASY_WAF_MCP_API_TOKEN", secret)
	t.Setenv("CROWDSEC_LAPI_KEY", "")
	t.Setenv("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080/")
	cleanRow := func(remove func(context.Context, string) error, id string) {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := remove(ctx, id); err != nil {
				t.Error(err)
			}
		})
	}
	allow := config.IPWLLocalEntry{CIDR: cidr, Comment: note}
	if err := st.UpsertIPWLLocal(t.Context(), &allow); err != nil {
		t.Fatal(err)
	}
	cleanRow(st.DeleteIPWLLocal, allow.ID)
	for _, row := range []config.IPBLLocalEntry{
		{CIDR: cidr, Enabled: true, Note: note},
		{CIDR: ip, Enabled: false, Note: note},
	} {
		if err := st.UpsertIPBLLocal(t.Context(), &row); err != nil {
			t.Fatal(err)
		}
		cleanRow(st.DeleteIPBLLocal, row.ID)
	}
	eng := engine.New(t.TempDir(), st, config.GlobalSettings{GeoIPEnabled: true})
	eng.GeoIP().Cache.Set(ip, "NL")
	server := &Server{Eng: eng, MCPAPIToken: auth.LoadMCPAPIToken(nil)}
	r := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/mcp/diagnostics/why-blocked?ip="+url.QueryEscape(ip), nil)
	r.RemoteAddr = "127.0.0.1:31000"
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, r)
	var got mcpIPBlockingEvidence
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil ||
		got.IP != ip || got.GeoIPCountry != "NL" || got.CrowdSecBan != "not_configured" ||
		got.RequestObservation != "not_checked" ||
		got.LocalAllowlistMatches == nil || *got.LocalAllowlistMatches != 1 ||
		got.LocalBlocklistMatches == nil || *got.LocalBlocklistMatches != 1 ||
		strings.Contains(w.Body.String(), note) {
		t.Fatalf("unexpected IP evidence: %d %s", w.Code, w.Body)
	}
}

func TestMCPCertificateExpiryOmitsProviderErrorAndPaths(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)
	cert := config.Certificate{
		ID: "test", PrimaryDomain: "public.example.test", ACMEStatus: "failed", NotAfter: &expiry,
		LastError: "fixture secret", DNSCredentialsEnvFile: "/fixture/private.env",
	}
	have := summarizeMCPCertificateExpiry([]config.Certificate{cert}, now)
	if len(have) != 1 || have[0].Status != "failed" || have[0].DaysRemaining == nil || *have[0].DaysRemaining != 1 {
		t.Fatalf("unexpected expiry result: %+v", have)
	}
	data, err := json.Marshal(have)
	if err != nil || strings.Contains(string(data), "fixture") || strings.Contains(string(data), "last_error") {
		t.Fatalf("unexpected certificate output %s: %v", data, err)
	}
}

func TestMCPApplicationSummaryKeepsOnlyPublicationMetadata(t *testing.T) {
	app := config.Application{
		ID: "test", Name: "Test", PublicHost: "app.example.test", Profile: "balanced", Enabled: true,
		BackendHost: "internal.example.test", ForwardAuthURL: "https://auth.example.test/?secret=fixture",
	}
	data, err := json.Marshal(summarizeMCPApplications([]config.Application{app}))
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"id":"test","name":"Test","public_host":"app.example.test","profile":"balanced","enabled":true,"maintenance":false}]`
	if string(data) != want {
		t.Fatalf("got %s, want %s", data, want)
	}
}
