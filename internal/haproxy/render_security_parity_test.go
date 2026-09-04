// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestListenModeSecurityParity(t *testing.T) {
	needles := []string{
		"app_sec1_white src -f",
		"app_sec1_black src -f",
		"app_sec1_empty_ua",
		"app_sec1_sqli query",
		"http-request send-spoe-group crowdsec crowdsec-req",
		"app_sec1_rp_0_path path_beg /admin",
	}
	for _, mode := range []string{"http_only", "https_only", "http_and_https"} {
		t.Run(mode, func(t *testing.T) {
			in := goldenListenModeFullSec(mode, "parity.example.local", "testdata/golden/certs/bundle-a.pem", false)
			if mode == "http_only" {
				in.Applications[0].CertificateID = ""
				in.Certificates = map[string]config.Certificate{}
			}
			r, err := Render(in)
			if err != nil {
				t.Fatal(err)
			}
			cfg := r.HAProxyConfig
			for _, n := range needles {
				if !strings.Contains(cfg, n) {
					t.Fatalf("mode %s missing %q", mode, n)
				}
			}
			if strings.Count(cfg, "stick-table type ip") != 1 {
				t.Fatalf("rate limit must be on the shared backend once, got %d stick-tables", strings.Count(cfg, "stick-table type ip"))
			}
			switch mode {
			case "http_only":
				if !strings.Contains(cfg, "frontend fe_http") {
					t.Fatal("expected fe_http")
				}
				if strings.Contains(cfg, "frontend fe_https") {
					t.Fatal("http_only must not emit fe_https")
				}
				if !strings.Contains(cfg, "http-request send-spoe-group crowdsec crowdsec-req if http_app_sec1_host !acme") {
					t.Fatal("CrowdSec on HTTP must skip ACME")
				}
				if !strings.Contains(cfg, "filter spoe engine crowdsec") {
					t.Fatal("expected SPOE filter on HTTP frontend")
				}
			case "https_only":
				if !strings.Contains(cfg, "http-request send-spoe-group crowdsec crowdsec-req if app_sec1_host") {
					t.Fatal("CrowdSec on HTTPS")
				}
			case "http_and_https":
				if !strings.Contains(cfg, "if http_app_sec1_host !acme") {
					t.Fatal("HTTP frontend must apply app security with ACME exclusion")
				}
				if !strings.Contains(cfg, "if app_sec1_host") {
					t.Fatal("HTTPS frontend must apply app security")
				}
				if strings.Count(cfg, "filter spoe engine crowdsec") != 2 {
					t.Fatalf("expected SPOE filter on both frontends, got %d", strings.Count(cfg, "filter spoe engine crowdsec"))
				}
			}
		})
	}
}

func TestBackendTLSRenderModes(t *testing.T) {
	t.Run("required", func(t *testing.T) {
		in := goldenListenModeFullSec("https_only", "verify.example.local", "testdata/golden/certs/bundle-a.pem", true)
		r, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.HAProxyConfig, "ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt") {
			t.Fatal(r.HAProxyConfig)
		}
		if !strings.Contains(r.HAProxyConfig, "verifyhost 10.0.9.9") {
			t.Fatal("expected verifyhost on backend IP")
		}
	})
	t.Run("custom CA", func(t *testing.T) {
		in := goldenListenModeFullSec("https_only", "customca.example.local", "testdata/golden/certs/bundle-a.pem", true)
		in.Applications[0].BackendTLSCAFile = "/etc/easy-waf/ca/lab.pem"
		in.Applications[0].BackendTLSServerName = "backend.lab.internal"
		r, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.HAProxyConfig, "ca-file /etc/easy-waf/ca/lab.pem") {
			t.Fatal("custom CA")
		}
		if !strings.Contains(r.HAProxyConfig, "sni str(backend.lab.internal) verifyhost backend.lab.internal") {
			t.Fatal("SNI/verifyhost override")
		}
	})
	t.Run("insecure override", func(t *testing.T) {
		in := goldenListenModeFullSec("https_only", "insecure.example.local", "testdata/golden/certs/bundle-a.pem", true)
		in.Applications[0].BackendTLSVerify = config.BackendTLSVerifyNone
		r, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.HAProxyConfig, "ssl verify none") {
			t.Fatal("expected verify none")
		}
		if strings.Contains(r.HAProxyConfig, "ssl verify required") {
			t.Fatal("insecure override must not emit verify required")
		}
	})
}

func TestACMEChallengeNotDeniedOnHTTP(t *testing.T) {
	in := goldenListenModeFullSec("http_only", "acme.example.local", "", false)
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.HAProxyConfig, "use_backend bk_acme if acme") {
		t.Fatal("ACME backend")
	}
	if !strings.Contains(r.HAProxyConfig, "acl acme path_beg /.well-known/acme-challenge/") {
		t.Fatal("ACME ACL")
	}
}
