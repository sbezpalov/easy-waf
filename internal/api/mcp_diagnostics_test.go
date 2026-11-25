// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	s := &Server{Eng: engine.New(t.TempDir(), st, config.GlobalSettings{}), MCPAPIToken: auth.LoadMCPAPIToken(nil)}
	router := s.Router()
	start := time.Now().Add(-time.Second)
	for _, route := range []struct{ suffix, want string }{
		{"/ready", `"database":"ok"`}, {"/edge", `"saved_generation"`}, {"/applications", "["},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/mcp/diagnostics"+route.suffix, nil)
		r.RemoteAddr = "127.0.0.1:31000"
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), route.want) {
			t.Fatalf("%s: unexpected response %d: %s", route.suffix, w.Code, w.Body)
		}
	}
	rows, _, err := st.ListAuditLogs(t.Context(), store.AuditListParams{Limit: 3, From: &start, Action: "mcp.diagnostics"})
	if err != nil || len(rows) != 3 {
		t.Fatalf("expected three MCP audit records, got %d: %v", len(rows), err)
	}
	for i, suffix := range []string{"/applications", "/edge", "/ready"} {
		entry := rows[i]
		if entry.UserName != "mcp" || !strings.Contains(string(entry.Details), "/api/v1/mcp/diagnostics"+suffix) {
			t.Fatalf("unexpected MCP audit record: %+v", entry)
		}
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
