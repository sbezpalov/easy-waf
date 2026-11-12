// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func renderStateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".render-state-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(abs) })
	return abs
}

func TestRenderHAMCPPreset(t *testing.T) {
	in := goldenFixture("ha-mcp")
	got, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := got.HAProxyConfig
	for _, needle := range []string{
		"deny deny_status 404",
		"path -m str /api/mcp /mcp_server/sse /auth /.well-known/oauth-authorization-server",
		`req.hdr(Authorization) -m beg "Bearer "`,
		"deny deny_status 401",
		"timeout client 3600s",
		"timeout http-request 10s",
		"http-request set-timeout server 3600s if",
		"sc1_http_req_rate(",
		"gt 20",
		"gt 10",
		"stick-table type ip size 50k",
		"timeout server 3600s",
		"path_beg /.git",
		"_rp_",
	} {
		if needle == "_rp_" {
			if strings.Contains(cfg, needle) {
				t.Fatal("preset must not invent restricted paths")
			}
			continue
		}
		if !strings.Contains(cfg, needle) {
			t.Errorf("missing %q", needle)
		}
	}
	if strings.Contains(cfg, "capture request header") {
		t.Fatal("httplog must not capture headers")
	}
	if strings.Contains(cfg, "option\thttplog") && strings.Contains(cfg, "Authorization") {
		// Authorization appears only in the ACL, never as a captured or logged header value.
		if strings.Contains(cfg, "capture request header Authorization") {
			t.Fatal("Authorization would be written to the log")
		}
	}
}

func TestRenderEdgeTokenIsFileNotValue(t *testing.T) {
	dir := renderStateDir(t)
	const secret = "edge-secret-value-not-for-config"
	app := config.Application{
		ID:          "edge1",
		Name:        "Edge",
		PublicHost:  "edge.example.com",
		BackendHost: "10.0.0.8",
		BackendPort: 8080,
		Profile:     "balanced",
		Enabled:     true,
		ListenMode:  "http_only",
		PathPolicy: &config.PathPolicy{
			Rules: []config.PathRule{{
				PathPrefix:          "/api/mcp",
				EdgeTokenHeader:     "X-Edge-Token",
				EdgeTokenConfigured: true,
			}},
		},
	}
	file, err := config.EdgeTokenFile(dir, app.ID, "/api/mcp", "X-Edge-Token")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"/secrets/edge-tokens/"+app.ID, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.DefaultSettings("/var/lib/easy-waf")
	settings.SPOEConfigPath = ""
	in := RenderInput{
		Settings:     settings,
		StateDir:     dir,
		Applications: []config.Application{app},
	}
	got, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := got.HAProxyConfig
	if strings.Contains(cfg, secret) {
		t.Fatal("edge token value was copied into haproxy.cfg")
	}
	if !strings.Contains(cfg, "-f "+file) {
		t.Fatalf("token file not referenced:\n%s", cfg)
	}
	if !strings.Contains(cfg, "http-request del-header X-Edge-Token") {
		t.Fatal("edge token header is not removed before the backend")
	}
	if strings.Contains(cfg, "capture request header") {
		t.Fatal("request headers are captured")
	}
}

func TestRenderRejectsMissingEdgeToken(t *testing.T) {
	dir := renderStateDir(t)
	settings := config.DefaultSettings("/var/lib/easy-waf")
	settings.SPOEConfigPath = ""
	in := RenderInput{
		Settings: settings,
		StateDir: dir,
		Applications: []config.Application{{
			ID: "edge1", Name: "Edge", PublicHost: "edge.example.com",
			BackendHost: "10.0.0.8", BackendPort: 8080, Profile: "balanced", Enabled: true,
			ListenMode: "http_only",
			PathPolicy: &config.PathPolicy{Rules: []config.PathRule{{
				PathPrefix: "/api/mcp", EdgeTokenHeader: "X-Edge-Token", EdgeTokenConfigured: true,
			}}},
		}},
	}
	if _, err := Render(in); err == nil {
		t.Fatal("missing token file must fail closed")
	}
}
