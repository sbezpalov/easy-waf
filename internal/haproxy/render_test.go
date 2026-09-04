// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestRenderProfileWiring(t *testing.T) {
	in := RenderInput{
		Settings: config.DefaultSettings("/tmp/state"),
		Applications: []config.Application{
			{
				ID:            "a1",
				Name:          "Test",
				PublicHost:    "app.example.com",
				BackendHost:   "10.0.0.1",
				BackendPort:   8080,
				Profile:       "balanced",
				CertificateID: "c1",
				Enabled:       true,
			},
		},
		Certificates: map[string]config.Certificate{
			"c1": {ID: "c1", BundlePath: "/tmp/state/certs/app.pem"},
		},
		CRTListPath: "/tmp/state/haproxy/crt-list.txt",
	}
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.HAProxyConfig
	if !strings.Contains(cfg, "stick-table type ip") {
		t.Error("expected per-backend stick-table for rate limiting")
	}
	if !strings.Contains(cfg, "sc0_http_req_rate gt 100") {
		t.Error("expected RateLimitBurst (100 for balanced) in rate limit ACL")
	}
	if !strings.Contains(cfg, "timeout server 50s") {
		t.Error("expected profile server timeout in backend")
	}
	if !strings.Contains(cfg, "path_beg /.git") {
		t.Error("expected profile block path (path_beg /.git) in frontend rules")
	}
}
