// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// goldenScenarioNames must match testdata/golden/<name>.cfg and <name>.crt-list.txt
var goldenScenarioNames = []string{
	"single-app-balanced",
	"multi-app-sni",
	"full-stack",
	"strict-profile",
	"trusted-lan",
	"waf-rules-enabled",
	"waf-rules-disabled",
	"app-with-restricted-path",
	"app-full-protection",
	"app-balanced",
	"app-trusted-lan",
	"app-reverse-proxy-only",
	"app-custom-partial",
	"mixed-apps",
	"http-only-app",
	"mixed-listen-modes",
	"http-only-reverse-proxy",
	"backend-by-hostname",
	"backend-by-ip",
	"listen-http-only-full-sec",
	"listen-https-only-full-sec",
	"listen-http-and-https-full-sec",
	"backend-tls-verify-required",
	"backend-tls-custom-ca",
	"backend-tls-verify-none",
}

func goldenGlobalSettings(spoePath, engine string) config.GlobalSettings {
	return config.GlobalSettings{
		ACMEStaging:              true,
		SPOEConfigPath:           spoePath,
		HAProxyConfigPath:        "testdata/golden/state/haproxy/haproxy.cfg",
		HAProxyStatsSocketPath:   "/run/haproxy/easy-waf-admin.sock",
		HAProxyBinary:            "/usr/sbin/haproxy",
		CrowdSecEngineName:       engine,
		GeoIPCacheTTL:            config.Duration(24 * time.Hour),
		ACMERenewalInterval:      config.Duration(12 * time.Hour),
		ACMEWebrootPath:          "testdata/golden/state/acme/webroot",
		IPBlacklistMapPath:       "testdata/golden/ipbl/test.map",
		IPBLExternalEnabled:      false,
		WAFBasicRulesEnabled:     false,
		BlockEmptyUA:             false,
		BlockedUserAgentsEnabled: false,
		BlockedUserAgentsMapPath: "testdata/golden/state/haproxy/blocked_ua.map",
		ManagementAllowedCIDRs:   config.DefaultManagementCIDRs(),
	}
}

func goldenFixture(name string) RenderInput {
	spoeMin := "testdata/golden/spoe/minimal-spoe.cfg"
	spoeCustom := "testdata/golden/spoe/crowdsec-custom.cfg"
	ipbl := "testdata/golden/ipbl/test.map"

	certA := "testdata/golden/certs/bundle-a.pem"
	certB := "testdata/golden/certs/bundle-b.pem"
	certC := "testdata/golden/certs/bundle-c.pem"

	switch name {
	case "single-app-balanced":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "a1",
					Name:          "App A",
					PublicHost:    "a.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/single-app-balanced.crt-list.txt",
		}
	case "multi-app-sni":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "a1",
					Name:          "App A",
					PublicHost:    "a.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
				},
				{
					ID:            "a2",
					Name:          "App B",
					PublicHost:    "b.example.org",
					BackendHost:   "10.0.0.2",
					BackendPort:   8123,
					Profile:       "home-assistant",
					CertificateID: "c2",
					Enabled:       true,
					WebSocket:     true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
				"c2": {ID: "c2", BundlePath: certB},
			},
			CRTListPath: "testdata/golden/multi-app-sni.crt-list.txt",
		}
	case "full-stack":
		return RenderInput{
			Settings:           goldenGlobalSettings(spoeCustom, "ew_cs_engine"),
			UseIPBlacklist:     true,
			IPBlacklistMapPath: ipbl,
			Applications: []config.Application{
				{
					ID:            "fs1",
					Name:          "Edge A",
					PublicHost:    "a.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
				},
				{
					ID:            "fs2",
					Name:          "Edge B",
					PublicHost:    "b.example.org",
					BackendHost:   "10.0.0.2",
					BackendPort:   8123,
					Profile:       "home-assistant",
					CertificateID: "c2",
					Enabled:       true,
					WebSocket:     true,
				},
				{
					ID:            "fs3",
					Name:          "Edge C",
					PublicHost:    "c.example.net",
					BackendHost:   "10.0.0.3",
					BackendPort:   443,
					Profile:       "public-app",
					CertificateID: "c3",
					Enabled:       true,
					BackendHTTPS:  true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
				"c2": {ID: "c2", BundlePath: certB},
				"c3": {ID: "c3", BundlePath: certC},
			},
			CRTListPath: "testdata/golden/full-stack.crt-list.txt",
		}
	case "strict-profile":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "s1",
					Name:          "Strict",
					PublicHost:    "strict.example.com",
					BackendHost:   "10.0.0.10",
					BackendPort:   9000,
					Profile:       "strict",
					CertificateID: "c1",
					Enabled:       true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/strict-profile.crt-list.txt",
		}
	case "trusted-lan":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "t1",
					Name:          "LAN",
					PublicHost:    "lan.home.arpa",
					BackendHost:   "192.168.1.50",
					BackendPort:   80,
					Profile:       "trusted-lan",
					CertificateID: "c1",
					Enabled:       true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/trusted-lan.crt-list.txt",
		}
	case "waf-rules-enabled":
		gs := goldenGlobalSettings(spoeMin, "crowdsec")
		sec := config.DefaultApplicationSecurity()
		sec.BasicWAFEnabled = true
		return RenderInput{
			Settings:       gs,
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "w1",
					Name:          "WAF on",
					PublicHost:    "waf-on.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/waf-rules-enabled.crt-list.txt",
		}
	case "waf-rules-disabled":
		sec := config.DefaultApplicationSecurity()
		sec.BasicWAFEnabled = false
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "w0",
					Name:          "WAF off",
					PublicHost:    "waf-off.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/waf-rules-disabled.crt-list.txt",
		}
	case "app-with-restricted-path":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "ha1",
					Name:          "Home Assistant",
					PublicHost:    "ha.example.com",
					BackendHost:   "192.168.1.10",
					BackendPort:   8123,
					Profile:       "home-assistant",
					CertificateID: "c1",
					Enabled:       true,
					WebSocket:     true,
					RestrictedPaths: []config.RestrictedPath{
						{
							PathPrefix:   "/api",
							AllowedCIDRs: []string{"192.168.0.0/16", "10.0.0.0/8"},
						},
					},
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/app-with-restricted-path.crt-list.txt",
		}
	case "app-full-protection":
		var sec config.ApplicationSecurity
		profiles.ApplyMode(&sec, profiles.ModeFull)
		sec.GeoIPCountryList = []string{"US"}
		sec.GeoIPPolicy = "allow"
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "full1",
					Name:          "Full",
					PublicHost:    "full.example.com",
					BackendHost:   "10.0.0.1",
					BackendPort:   8080,
					Profile:       "strict",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/app-full-protection.crt-list.txt",
		}
	case "app-balanced":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "bal1",
					Name:          "Balanced",
					PublicHost:    "balanced.example.com",
					BackendHost:   "10.0.0.2",
					BackendPort:   80,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/app-balanced.crt-list.txt",
		}
	case "app-trusted-lan":
		var sec config.ApplicationSecurity
		profiles.ApplyMode(&sec, profiles.ModeTrustedLAN)
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "tl1",
					Name:          "Trusted",
					PublicHost:    "trusted.example.com",
					BackendHost:   "10.0.0.3",
					BackendPort:   80,
					Profile:       "trusted-lan",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/app-trusted-lan.crt-list.txt",
		}
	case "app-reverse-proxy-only":
		var sec config.ApplicationSecurity
		profiles.ApplyMode(&sec, profiles.ModeReverseProxyOnly)
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "dbg1",
					Name:          "Debug",
					PublicHost:    "debug.example.com",
					BackendHost:   "10.0.0.5",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/app-reverse-proxy-only.crt-list.txt",
		}
	case "app-custom-partial":
		sec := config.ApplicationSecurity{
			Mode:             "custom",
			BasicWAFEnabled:  true,
			CrowdSecEnabled:  true,
			GeoIPPolicy:      "allow",
			GeoIPCountryList: nil,
		}
		config.NormalizeApplicationSecurity(&sec)
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID:            "cust1",
					Name:          "Custom",
					PublicHost:    "custom.example.com",
					BackendHost:   "10.0.0.9",
					BackendPort:   8080,
					Profile:       "balanced",
					CertificateID: "c1",
					Enabled:       true,
					Security:      sec,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/app-custom-partial.crt-list.txt",
		}
	case "mixed-apps":
		secFull := config.DefaultApplicationSecurity()
		profiles.ApplyMode(&secFull, profiles.ModeFull)
		secFull.GeoIPEnabled = false
		secDbg := config.DefaultApplicationSecurity()
		profiles.ApplyMode(&secDbg, profiles.ModeReverseProxyOnly)
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "m1", Name: "One", PublicHost: "m1.example.com", BackendHost: "10.0.1.1", BackendPort: 80,
					Profile: "strict", CertificateID: "c1", Enabled: true, Security: secFull,
				},
				{
					ID: "m2", Name: "Two", PublicHost: "m2.example.com", BackendHost: "10.0.1.2", BackendPort: 80,
					Profile: "balanced", CertificateID: "c2", Enabled: true, Security: secDbg,
				},
				{
					ID: "m3", Name: "Three", PublicHost: "m3.example.com", BackendHost: "10.0.1.3", BackendPort: 80,
					Profile: "balanced", CertificateID: "c1", Enabled: true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
				"c2": {ID: "c2", BundlePath: certB},
			},
			CRTListPath: "testdata/golden/mixed-apps.crt-list.txt",
		}
	case "http-only-app":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "ho1", Name: "Plain", PublicHost: "plain.example.local", BackendHost: "192.168.1.50", BackendPort: 80,
					Profile: "balanced", CertificateID: "", ListenMode: "http_only", Enabled: true,
				},
			},
			Certificates: map[string]config.Certificate{},
			CRTListPath:  "testdata/golden/http-only-app.crt-list.txt",
		}
	case "mixed-listen-modes":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "x1", Name: "HTTPS", PublicHost: "app-https.test", BackendHost: "10.0.2.1", BackendPort: 443, BackendHTTPS: true,
					Profile: "balanced", CertificateID: "cA", ListenMode: "https_only", Enabled: true,
				},
				{
					ID: "x2", Name: "HTTP", PublicHost: "app-http.test", BackendHost: "10.0.2.2", BackendPort: 80,
					Profile: "balanced", CertificateID: "", ListenMode: "http_only", Enabled: true,
				},
				{
					ID: "x3", Name: "Both", PublicHost: "app-both.test", BackendHost: "10.0.2.3", BackendPort: 8080,
					Profile: "balanced", CertificateID: "cB", ListenMode: "http_and_https", Enabled: true,
				},
			},
			Certificates: map[string]config.Certificate{
				"cA": {ID: "cA", BundlePath: certA},
				"cB": {ID: "cB", BundlePath: certB},
			},
			CRTListPath: "testdata/golden/mixed-listen-modes.crt-list.txt",
		}
	case "http-only-reverse-proxy":
		var sec config.ApplicationSecurity
		profiles.ApplyMode(&sec, profiles.ModeReverseProxyOnly)
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "ior1", Name: "IoT", PublicHost: "iot.lan", BackendHost: "192.168.55.1", BackendPort: 80,
					Profile: "balanced", CertificateID: "", ListenMode: "http_only", Enabled: true, Security: sec,
				},
			},
			Certificates: map[string]config.Certificate{},
			CRTListPath:  "testdata/golden/http-only-reverse-proxy.crt-list.txt",
		}
	case "backend-by-hostname":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "bh1", Name: "NAS", PublicHost: "nas.example.com", BackendHost: "nas.lan", BackendPort: 8080,
					Profile: "balanced", CertificateID: "c1", Enabled: true,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/backend-by-hostname.crt-list.txt",
		}
	case "backend-by-ip":
		return RenderInput{
			Settings:       goldenGlobalSettings(spoeMin, "crowdsec"),
			UseIPBlacklist: false,
			Applications: []config.Application{
				{
					ID: "bi1", Name: "ByIP", PublicHost: "ip.example.com", BackendHost: "10.0.0.9", BackendPort: 80,
					Profile: "balanced", CertificateID: "c1", Enabled: true,
				},
			},
			Certificates: map[string]config.Certificate{"c1": {ID: "c1", BundlePath: certA}},
			CRTListPath:  "testdata/golden/backend-by-ip.crt-list.txt",
		}
	case "listen-http-only-full-sec":
		return goldenListenModeFullSec("http_only", "plain-sec.example.local", "", false)
	case "listen-https-only-full-sec":
		return goldenListenModeFullSec("https_only", "tls-sec.example.local", certA, false)
	case "listen-http-and-https-full-sec":
		return goldenListenModeFullSec("http_and_https", "both-sec.example.local", certA, false)
	case "backend-tls-verify-required":
		return goldenListenModeFullSec("https_only", "verify.example.local", certA, true)
	case "backend-tls-custom-ca":
		in := goldenListenModeFullSec("https_only", "customca.example.local", certA, true)
		in.Applications[0].BackendTLSCAFile = "/etc/easy-waf/ca/lab.pem"
		in.Applications[0].BackendTLSServerName = "backend.lab.internal"
		in.CRTListPath = "testdata/golden/backend-tls-custom-ca.crt-list.txt"
		return in
	case "backend-tls-verify-none":
		in := goldenListenModeFullSec("https_only", "insecure.example.local", certA, true)
		in.Applications[0].BackendTLSVerify = config.BackendTLSVerifyNone
		in.CRTListPath = "testdata/golden/backend-tls-verify-none.crt-list.txt"
		return in
	default:
		return RenderInput{}
	}
}

func goldenListenModeFullSec(listenMode, host, certPath string, backendHTTPS bool) RenderInput {
	sec := config.DefaultApplicationSecurity()
	sec.GeoIPEnabled = false
	app := config.Application{
		ID: "sec1", Name: "Sec", PublicHost: host, BackendHost: "10.0.9.9", BackendPort: 443,
		Profile: "strict", Enabled: true, ListenMode: listenMode, Security: sec,
		RestrictedPaths: []config.RestrictedPath{{PathPrefix: "/admin", AllowedCIDRs: []string{"10.0.0.0/8"}}},
	}
	if backendHTTPS {
		app.BackendHTTPS = true
		app.BackendTLSVerify = config.BackendTLSVerifyRequired
	} else {
		app.BackendPort = 8080
	}
	in := RenderInput{
		Settings:           goldenGlobalSettings("testdata/golden/spoe/minimal-spoe.cfg", "crowdsec"),
		UseIPBlacklist:     true,
		UseIPAllowlist:     true,
		IPBlacklistMapPath: "testdata/golden/ipbl/test.map",
		IPAllowlistMapPath: "testdata/golden/ipbl/test.map",
		Applications:       []config.Application{app},
		Certificates:       map[string]config.Certificate{},
		CRTListPath:        "testdata/golden/listen-" + strings.ReplaceAll(listenMode, "_", "-") + "-full-sec.crt-list.txt",
	}
	in.Settings.BlockEmptyUA = true
	if certPath != "" {
		in.Applications[0].CertificateID = "c1"
		in.Certificates["c1"] = config.Certificate{ID: "c1", BundlePath: certPath}
	}
	switch listenMode {
	case "http_only":
		in.CRTListPath = "testdata/golden/listen-http-only-full-sec.crt-list.txt"
	case "https_only":
		if backendHTTPS && host == "verify.example.local" {
			in.CRTListPath = "testdata/golden/backend-tls-verify-required.crt-list.txt"
		} else {
			in.CRTListPath = "testdata/golden/listen-https-only-full-sec.crt-list.txt"
		}
	case "http_and_https":
		in.CRTListPath = "testdata/golden/listen-http-and-https-full-sec.crt-list.txt"
	}
	return in
}

func normalizeGoldenNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func TestGoldenRender(t *testing.T) {
	for _, name := range goldenScenarioNames {
		t.Run(name, func(t *testing.T) {
			in := goldenFixture(name)
			if in.Settings.SPOEConfigPath == "" {
				t.Fatalf("unknown golden fixture %q", name)
			}
			gotR, err := Render(in)
			if err != nil {
				t.Fatal(err)
			}
			got := normalizeGoldenNewlines(gotR.HAProxyConfig)
			crtWant := normalizeGoldenNewlines(gotR.CRTList)

			goldenDir := filepath.Join("testdata", "golden")
			cfgPath := filepath.Join(goldenDir, name+".cfg")
			crtPath := filepath.Join(goldenDir, name+".crt-list.txt")

			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfgPath, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(crtPath, []byte(crtWant), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Logf("UPDATE_GOLDEN: wrote %s and %s", cfgPath, crtPath)
				return
			}

			wantBytes, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatalf("read golden %s: %v (set UPDATE_GOLDEN=1 to create)", cfgPath, err)
			}
			want := normalizeGoldenNewlines(string(wantBytes))
			if got != want {
				t.Fatalf("golden mismatch %s: diff (got vs want) — re-run with UPDATE_GOLDEN=1 after reviewing\n--- got (first 800 bytes):\n%s\n--- want (first 800 bytes):\n%s",
					name, truncateMsg(got, 800), truncateMsg(want, 800))
			}

			crtGolden, err := os.ReadFile(crtPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", crtPath, err)
			}
			if crtWant != normalizeGoldenNewlines(string(crtGolden)) {
				t.Fatalf("crt-list golden mismatch for %s", name)
			}
		})
	}
}

func truncateMsg(s string, n int) string {
	s = strings.ReplaceAll(s, "\t", "\\t")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func TestGoldenWAFRuleScenarios(t *testing.T) {
	t.Run("waf-rules-enabled", func(t *testing.T) {
		in := goldenFixture("waf-rules-enabled")
		if in.Settings.SPOEConfigPath == "" {
			t.Fatal("fixture waf-rules-enabled missing")
		}
		if !in.Applications[0].Security.BasicWAFEnabled {
			t.Fatal("expected per-app BasicWAFEnabled true")
		}
		gotR, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		cfg := gotR.HAProxyConfig
		for _, needle := range []string{
			"acl app_",
			"_sqli query",
			"_sqli_path path",
			"_xss query",
			"_xss_path path",
			"_traversal path",
			"http-request deny deny_status 403 if app_",
			"_host app_",
			"_sqli",
		} {
			if !strings.Contains(cfg, needle) {
				t.Fatalf("expected rendered config to contain %q", needle)
			}
		}
		if strings.Contains(cfg, `|\.\.[\]`) || strings.Contains(cfg, `|\.\.[\\]`) {
			t.Fatal("waf_traversal must not use a ..\\ branch in one ACL regex (breaks haproxy -c)")
		}
		if !strings.Contains(cfg, `_traversal path -m reg -i \.\./`) {
			t.Fatal(`expected traversal ACL with "\.\./"`)
		}
	})
	t.Run("waf-rules-disabled", func(t *testing.T) {
		in := goldenFixture("waf-rules-disabled")
		if in.Settings.SPOEConfigPath == "" {
			t.Fatal("fixture waf-rules-disabled missing")
		}
		if in.Applications[0].Security.BasicWAFEnabled {
			t.Fatal("expected per-app BasicWAFEnabled false")
		}
		gotR, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(gotR.HAProxyConfig, "_sqli query") {
			t.Fatal("WAF ACLs must be absent when per-app basic_waf_enabled is false")
		}
	})
}

func TestGoldenRestrictedPathACLs(t *testing.T) {
	in := goldenFixture("app-with-restricted-path")
	if in.Settings.SPOEConfigPath == "" {
		t.Fatal("fixture app-with-restricted-path missing")
	}
	if len(in.Applications) != 1 || len(in.Applications[0].RestrictedPaths) != 1 {
		t.Fatal("expected one app with one restricted path")
	}
	gotR, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gotR.HAProxyConfig
	for _, needle := range []string{
		"# Per-app restricted path: Home Assistant /api",
		"acl app_",
		"_rp_0_path path_beg /api",
		"_rp_0_net src 192.168.0.0/16 10.0.0.0/8",
		"http-request deny deny_status 403 if app_",
		"_host app_",
		"_rp_0_path !app_",
		"_rp_0_net",
	} {
		if !strings.Contains(cfg, needle) {
			t.Fatalf("missing %q in rendered config", needle)
		}
	}
}
