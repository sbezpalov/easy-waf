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

const crowdSecDeny = `http-request return status 403 content-type "text/html; charset=utf-8" hdr Cache-Control no-store lf-string "<!doctype html><title>Access denied</title><h1>Access denied</h1><p>Your address %[src] is blocked on this site by CrowdSec, a shared reputation service. If this is a mistake, send this address to the site owner.</p>" if app_cs1_host { var(txn.crowdsec.remediation) -m found } !{ var(txn.crowdsec.remediation) -m str allow }`

func crowdSecInput(enabled bool) RenderInput {
	sec := config.DefaultApplicationSecurity()
	sec.CrowdSecEnabled = enabled
	return RenderInput{
		Settings: goldenGlobalSettings("testdata/golden/spoe/crowdsec-vendor.cfg", "crowdsec"),
		Applications: []config.Application{{
			ID: "cs1", Name: "cs", PublicHost: "cs.example.com", BackendHost: "10.0.0.5", BackendPort: 8080,
			Profile: "balanced", ListenMode: "https_only", Enabled: true, CertificateID: "c1", Security: sec,
		}},
		Certificates: map[string]config.Certificate{"c1": {ID: "c1", PrimaryDomain: "cs.example.com", BundlePath: "/tmp/cs.pem"}},
		CRTListPath:  "/tmp/crt-list.txt",
	}
}

// A decision has no effect unless the generated config acts on the bouncer's
// answer: the SPOE call on its own only sets a variable.
func TestCrowdSecDecisionsAreEnforced(t *testing.T) {
	r, err := Render(crowdSecInput(true))
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.HAProxyConfig
	send := strings.Index(cfg, "http-request send-spoe-group crowdsec crowdsec-http-no-body if app_cs1_host")
	deny := strings.Index(cfg, crowdSecDeny)
	if send < 0 || deny < 0 {
		t.Fatalf("send at %d, deny at %d:\n%s", send, deny, cfg)
	}
	if deny < send {
		t.Fatal("the deny runs before the bouncer has answered")
	}
	for _, want := range []string{"unique-id-format %[uuid()]", "backend crowdsec-spoa", "server spoa 127.0.0.1:9000"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestCrowdSecDisabledRendersNoSPOE(t *testing.T) {
	r, err := Render(crowdSecInput(false))
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"filter spoe", "crowdsec-spoa", "txn.crowdsec", "unique-id-format"} {
		if strings.Contains(r.HAProxyConfig, unwanted) {
			t.Errorf("found %q with CrowdSec off", unwanted)
		}
	}
}

// The names are the vendor's; a bump of the pinned copy must keep them true.
func TestVendorSPOEFileMatchesGeneratedNames(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "golden", "spoe", "crowdsec-vendor.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[crowdsec]", "spoe-group crowdsec-http-no-body", "use-backend crowdsec-spoa", "var-prefix      crowdsec"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("vendor file lacks %q", want)
		}
	}
}
