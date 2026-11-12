// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestTLSPassthroughWithoutHTTPSApps(t *testing.T) {
	st := config.DefaultSettings("/var/lib/easy-waf")
	st.TLSPassthrough = []config.TLSPassthrough{{ServerName: "vpn.example.com", BackendHost: "10.0.0.5", BackendPort: 443, Enabled: true}}
	r, err := Render(RenderInput{Settings: st, CRTListPath: "/tmp/crt-list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.HAProxyConfig
	for _, want := range []string{"frontend fe_tls_in", "use_backend pt_vpn_example_com if { req_ssl_sni -i vpn.example.com }", "default_backend bk_tls_none"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(cfg, "frontend fe_https") || strings.Contains(cfg, "unix@") {
		t.Error("fe_https or its socket rendered without HTTPS apps")
	}
}

func TestTLSPassthroughCollidesWithApp(t *testing.T) {
	st := config.DefaultSettings("/var/lib/easy-waf")
	st.TLSPassthrough = []config.TLSPassthrough{{ServerName: "*.example.com", BackendHost: "10.0.0.5", BackendPort: 443, Enabled: true}}
	_, err := Render(RenderInput{Settings: st, Applications: []config.Application{
		{ID: "a", Name: "A", PublicHost: "web.example.com", BackendHost: "10.0.0.6", BackendPort: 80, Profile: "balanced", Enabled: true},
	}})
	if err == nil || !strings.Contains(err.Error(), "also covers application") {
		t.Fatalf("err = %v", err)
	}
	// An http_only app is not on :443, so it does not collide.
	_, err = Render(RenderInput{Settings: st, Applications: []config.Application{
		{ID: "a", Name: "A", PublicHost: "web.example.com", BackendHost: "10.0.0.6", BackendPort: 80, Profile: "balanced", ListenMode: "http_only", Enabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSChainSocketPathUsesTargetSeparators(t *testing.T) {
	if got, want := httpsChainSocketPath("/run/haproxy/easy-waf-admin.sock"), "/run/haproxy/easy-waf-https.sock"; got != want {
		t.Fatalf("httpsChainSocketPath() = %q, want %q", got, want)
	}
}
