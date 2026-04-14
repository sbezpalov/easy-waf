package haproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// goldenScenarioNames must match testdata/golden/<name>.cfg and <name>.crt-list.txt
var goldenScenarioNames = []string{
	"single-app-balanced",
	"multi-app-sni",
	"full-stack",
	"strict-profile",
	"trusted-lan",
}

func goldenGlobalSettings(spoePath, engine string) config.GlobalSettings {
	return config.GlobalSettings{
		ACMEStaging:            true,
		SPOEConfigPath:         spoePath,
		HAProxyConfigPath:      "testdata/golden/state/haproxy/haproxy.cfg",
		HAProxyBinary:          "/usr/sbin/haproxy",
		CrowdSecEngineName:     engine,
		GeoIPCacheTTL:          config.Duration(24 * time.Hour),
		ACMERenewalInterval:    config.Duration(12 * time.Hour),
		ACMEWebrootPath:        "testdata/golden/state/acme/webroot",
		IPBlacklistMapPath:     "testdata/golden/ipbl/test.map",
		IPBLExternalEnabled:    false,
		ManagementAllowedCIDRs: config.DefaultManagementCIDRs(),
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
					ID:             "a1",
					Name:           "App A",
					PublicHost:     "a.example.com",
					BackendHost:    "10.0.0.1",
					BackendPort:    8080,
					Profile:        "balanced",
					CertificateID:  "c1",
					Enabled:        true,
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
					ID:             "a1",
					Name:           "App A",
					PublicHost:     "a.example.com",
					BackendHost:    "10.0.0.1",
					BackendPort:    8080,
					Profile:        "balanced",
					CertificateID:  "c1",
					Enabled:        true,
				},
				{
					ID:             "a2",
					Name:           "App B",
					PublicHost:     "b.example.org",
					BackendHost:    "10.0.0.2",
					BackendPort:    8123,
					Profile:        "home-assistant",
					CertificateID:  "c2",
					Enabled:        true,
					WebSocket:      true,
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
					ID:             "fs1",
					Name:           "Edge A",
					PublicHost:     "a.example.com",
					BackendHost:    "10.0.0.1",
					BackendPort:    8080,
					Profile:        "balanced",
					CertificateID:  "c1",
					Enabled:        true,
				},
				{
					ID:             "fs2",
					Name:           "Edge B",
					PublicHost:     "b.example.org",
					BackendHost:    "10.0.0.2",
					BackendPort:    8123,
					Profile:        "home-assistant",
					CertificateID:  "c2",
					Enabled:        true,
					WebSocket:      true,
				},
				{
					ID:             "fs3",
					Name:           "Edge C",
					PublicHost:     "c.example.net",
					BackendHost:    "10.0.0.3",
					BackendPort:    443,
					Profile:        "public-app",
					CertificateID:  "c3",
					Enabled:        true,
					BackendHTTPS:   true,
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
					ID:             "s1",
					Name:           "Strict",
					PublicHost:     "strict.example.com",
					BackendHost:    "10.0.0.10",
					BackendPort:    9000,
					Profile:        "strict",
					CertificateID:  "c1",
					Enabled:        true,
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
					ID:             "t1",
					Name:           "LAN",
					PublicHost:     "lan.home.arpa",
					BackendHost:    "192.168.1.50",
					BackendPort:    80,
					Profile:        "trusted-lan",
					CertificateID:  "c1",
					Enabled:        true,
				},
			},
			Certificates: map[string]config.Certificate{
				"c1": {ID: "c1", BundlePath: certA},
			},
			CRTListPath: "testdata/golden/trusted-lan.crt-list.txt",
		}
	default:
		return RenderInput{}
	}
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
				if err := os.WriteFile(cfgPath, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(crtPath, []byte(crtWant), 0o644); err != nil {
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
