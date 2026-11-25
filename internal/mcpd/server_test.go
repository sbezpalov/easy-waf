// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mcpd

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/easy-waf/easy-waf/internal/auth"
)

func TestStreamableHTTPDiagnostics(t *testing.T) {
	const applicationID = "legacy id+fixture"
	clientSecret, apiSecret := strings.Repeat("c", 40), strings.Repeat("a", 40)
	t.Setenv("EASY_WAF_MCP_TOKEN", clientSecret)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+apiSecret {
			http.Error(w, "unexpected diagnostics request", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case diagnosticsPath + "/ready":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"database":"unreachable"}`)
		case diagnosticsPath + "/edge":
			_, _ = fmt.Fprint(w, `{"pending":false}`)
		case diagnosticsPath + "/applications":
			_, _ = fmt.Fprint(w, `[{"name":"Fixture"}]`)
		case diagnosticsPath + "/application":
			if r.URL.Query().Get("id") != applicationID {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprint(w, `{"status":"ok"}`)
		case diagnosticsPath + "/certificates", diagnosticsPath + "/revisions":
			_, _ = fmt.Fprint(w, `[]`)
		case diagnosticsPath + "/geoip":
			_, _ = fmt.Fprint(w, `{"configured_provider":"maxmind"}`)
		case diagnosticsPath + "/recent-events":
			_, _ = fmt.Fprint(w, `{"events":[],"has_more":false}`)
		case diagnosticsPath + "/why-blocked":
			if r.URL.Query().Get("ip") != "192.0.2.17" {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprint(w, `{"crowdsec_ban":"present","request_observation":"not_checked"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	ca := filepath.Join(t.TempDir(), "test-cert.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := newAPIClient(upstream.URL, ca, apiSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.http.CloseIdleConnections)
	server := httptest.NewServer(newHandler(api, auth.LoadStaticToken("EASY_WAF_MCP_TOKEN", 32)))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "integration-test", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: bearerTransport{clientSecret, server.Client().Transport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := session.InitializeResult().ProtocolVersion; got != protocolVersion {
		t.Fatalf("protocol = %q, want %q", got, protocolVersion)
	}
	checks := map[string]string{
		"edge_status": `{"pending":false}`, "list_applications": `[{"name":"Fixture"}]`, "status": `{"database":"unreachable"}`,
		"describe_application": `{"status":"ok"}`, "certificate_expiry": `[]`, "config_revisions": `[]`,
		"geoip_status":  `{"configured_provider":"maxmind"}`,
		"why_blocked":   `{"crowdsec_ban":"present","request_observation":"not_checked"}`,
		"recent_events": `{"events":[],"has_more":false}`,
	}
	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != len(checks) {
		t.Fatalf("expected %d diagnostics tools: %v, %v", len(checks), listed, err)
	}
	for _, tool := range listed.Tools {
		want, ok := checks[tool.Name]
		if !ok || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("unexpected tool: %+v", tool)
		}
		params := &mcp.CallToolParams{Name: tool.Name}
		switch tool.Name {
		case "describe_application":
			params.Arguments = map[string]string{"id": applicationID}
		case "why_blocked":
			params.Arguments = map[string]string{"ip": "::ffff:192.0.2.17"}
		}
		result, err := session.CallTool(ctx, params)
		if err != nil || len(result.Content) != 1 || result.IsError != (tool.Name == "status") {
			t.Fatalf("unexpected %s result: %v, %v", tool.Name, result, err)
		}
		if text, ok := result.Content[0].(*mcp.TextContent); !ok || text.Text != want {
			t.Fatalf("unexpected %s content: %v", tool.Name, result.Content)
		}
	}
}

type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.next.RoundTrip(r)
}

func TestMCPHTTPBoundary(t *testing.T) {
	clientSecret, apiSecret := strings.Repeat("c", 40), strings.Repeat("a", 40)
	t.Setenv("EASY_WAF_MCP_TOKEN", clientSecret)
	handler := protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), auth.LoadStaticToken("EASY_WAF_MCP_TOKEN", 32))
	for _, tc := range []struct {
		name, host, peer, origin, path, secret string
		want                                   int
	}{
		{"local", "127.0.0.1:8446", "127.0.0.1:50000", "", "/mcp", clientSecret, http.StatusNoContent},
		{"local IPv6", "[::1]:8446", "[::1]:50000", "", "/mcp", clientSecret, http.StatusNoContent},
		{"missing token", "localhost", "127.0.0.1:50000", "", "/mcp", "", http.StatusUnauthorized},
		{"wrong credential", "localhost", "127.0.0.1:50000", "", "/mcp", apiSecret, http.StatusUnauthorized},
		{"foreign host", "example.test", "127.0.0.1:50000", "", "/mcp", clientSecret, http.StatusForbidden},
		{"browser origin", "localhost", "127.0.0.1:50000", "http://localhost:8446", "/mcp", clientSecret, http.StatusForbidden},
		{"remote peer", "localhost", "192.0.2.1:50000", "", "/mcp", clientSecret, http.StatusForbidden},
		{"token in URL", "localhost", "127.0.0.1:50000", "", "/mcp?a=b", clientSecret, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, nil)
			r.Host, r.RemoteAddr = tc.host, tc.peer
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.secret != "" {
				r.Header.Set("Authorization", "Bearer "+tc.secret)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestMCPStartupConfiguration(t *testing.T) {
	t.Setenv("EASY_WAF_MCP_LISTEN", "")
	t.Setenv("EASY_WAF_MCP_TOKEN", "invalid")
	if err := Run(t.Context()); err != nil {
		t.Fatalf("disabled daemon: %v", err)
	}
	t.Setenv("EASY_WAF_MCP_LISTEN", "0.0.0.0:8446")
	if err := Run(t.Context()); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("wildcard bind was not refused: %v", err)
	}
	t.Setenv("EASY_WAF_MCP_LISTEN", "127.0.0.1:8446")
	secret := strings.Repeat("a", 40)
	t.Setenv("EASY_WAF_MCP_TOKEN", secret)
	t.Setenv("EASY_WAF_MCP_API_TOKEN", secret)
	if err := Run(t.Context()); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("reused credentials were not refused: %v", err)
	}
	for _, address := range []string{"https://example.test", "http://127.0.0.1:8443", "https://127.0.0.1/?token=fixture", "https://127.0.0.1/extra"} {
		if _, err := newAPIClient(address, "", ""); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("invalid API origin %q was not refused: %v", address, err)
		}
	}
}
