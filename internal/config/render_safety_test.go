// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSettingsAcceptsNativeStateDirectory(t *testing.T) {
	stateDir := t.TempDir()
	settings := DefaultSettings(stateDir)
	if err := ValidateSettingsRenderSafety(&settings); err != nil {
		t.Fatalf("native state directory produced unsafe defaults: %v", err)
	}
	want := filepath.ToSlash(filepath.Join(stateDir, "haproxy", "haproxy.cfg"))
	if settings.HAProxyConfigPath != want {
		t.Fatalf("HAProxy config path = %q, want %q", settings.HAProxyConfigPath, want)
	}
}

func safeApp() *Application {
	return &Application{
		ID:          "shop",
		Name:        "Shop",
		PublicHost:  "shop.example.com",
		BackendHost: "10.0.0.5",
		BackendPort: 8080,
	}
}

func TestValidateApplicationRenderSafety_acceptsNormalApp(t *testing.T) {
	if err := ValidateApplicationRenderSafety(safeApp()); err != nil {
		t.Fatalf("valid application rejected: %v", err)
	}
}

func TestValidateAbsoluteConfigFilePathUsesTargetSemantics(t *testing.T) {
	for _, value := range []string{"/etc/easy-waf/easy-waf.env", "/var/lib/easy-waf/maps/ip.map"} {
		if err := ValidateAbsoluteConfigFilePath("path", value, false); err != nil {
			t.Fatalf("%q rejected: %v", value, err)
		}
	}
	for _, value := range []string{
		`C:\etc\easy-waf\easy-waf.env`,
		"relative/path",
		"/etc/easy-waf/../shadow",
		"/etc/easy-waf//easy-waf.env",
		" /etc/easy-waf/easy-waf.env",
		"/etc/easy-waf/easy-waf.env ",
	} {
		if err := ValidateAbsoluteConfigFilePath("path", value, false); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
	if !TargetPathWithin("/etc/easy-waf/ca/lab.pem", "/etc/easy-waf/ca") {
		t.Fatal("valid child path rejected")
	}
	for _, value := range []string{"/etc/easy-waf/ca", "/etc/easy-waf/cab/lab.pem", "/etc/easy-waf/ca/../shadow"} {
		if TargetPathWithin(value, "/etc/easy-waf/ca") {
			t.Fatalf("escaping path %q accepted", value)
		}
	}
}

// A newline in any rendered field would close the current HAProxy directive and
// start a new one — the resulting config is still syntactically valid, so
// `haproxy -c` would not catch it.
func TestValidateApplicationRenderSafety_rejectsConfigInjection(t *testing.T) {
	cases := map[string]func(*Application){
		"newline in public_host":  func(a *Application) { a.PublicHost = "shop.example.com\n    http-request allow" },
		"newline in backend_host": func(a *Application) { a.BackendHost = "10.0.0.5\n    server evil 1.2.3.4:80" },
		"newline in name":         func(a *Application) { a.Name = "Shop\nfrontend evil" },
		"space in public_host":    func(a *Application) { a.PublicHost = "shop.example.com evil.com" },
		"comment in public_host":  func(a *Application) { a.PublicHost = "shop.example.com#" },
		"semicolon in backend":    func(a *Application) { a.BackendHost = "10.0.0.5;reboot" },
		"tab in public_host":      func(a *Application) { a.PublicHost = "shop.example.com\tx" },
		"bad health path":         func(a *Application) { a.HealthPath = "/health\n    http-request allow" },
		"bad path prefix":         func(a *Application) { a.PathPrefix = "/api or true" },
		"bad sni":                 func(a *Application) { a.BackendTLSServerName = "a) if TRUE" },
		"zero port":               func(a *Application) { a.BackendPort = 0 },
		"huge port":               func(a *Application) { a.BackendPort = 70000 },
		"long name":               func(a *Application) { a.Name = strings.Repeat("x", 201) },
	}
	for name, mutate := range cases {
		app := safeApp()
		mutate(app)
		if err := ValidateApplicationRenderSafety(app); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestValidateApplicationRenderSafety_restrictedPaths(t *testing.T) {
	app := safeApp()
	app.RestrictedPaths = []RestrictedPath{{PathPrefix: "/admin", AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.4"}}}
	if err := ValidateApplicationRenderSafety(app); err != nil {
		t.Fatalf("valid restricted path rejected: %v", err)
	}

	app.RestrictedPaths = []RestrictedPath{{PathPrefix: "/admin", AllowedCIDRs: []string{"10.0.0.0/8 or always_true"}}}
	if err := ValidateApplicationRenderSafety(app); err == nil {
		t.Fatal("injected CIDR accepted")
	}

	app.RestrictedPaths = []RestrictedPath{{PathPrefix: "/admin\n    http-request allow"}}
	if err := ValidateApplicationRenderSafety(app); err == nil {
		t.Fatal("injected restricted path accepted")
	}
}

func TestValidateBackendTLSServerName(t *testing.T) {
	for _, ok := range []string{"", "backend.internal", "10.0.0.5", "*.example.com", "svc.local:8443"} {
		if err := ValidateBackendTLSServerName(ok); err != nil {
			t.Fatalf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"a)", "a(b", "name with space", "a;b", "a#b", "a\nb", strings.Repeat("a", 254)} {
		if err := ValidateBackendTLSServerName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestValidateSettingsRenderSafety_realIP(t *testing.T) {
	ok := GlobalSettings{
		TrustedProxyCIDRs:  []string{"173.245.48.0/20", "2400:cb00::/32", "10.0.0.1"},
		RealIPHeader:       "CF-Connecting-IP",
		ProxyProtocolCIDRs: []string{"192.168.88.1"},
	}
	if err := ValidateSettingsRenderSafety(&ok); err != nil {
		t.Fatalf("valid real IP settings rejected: %v", err)
	}
	cases := map[string]func(*GlobalSettings){
		"newline in trusted proxy": func(s *GlobalSettings) { s.TrustedProxyCIDRs = []string{"10.0.0.0/8 }\n\thttp-request allow"} },
		"hostname as proxy":        func(s *GlobalSettings) { s.TrustedProxyCIDRs = []string{"cdn.example.com"} },
		"bad proxy protocol cidr":  func(s *GlobalSettings) { s.ProxyProtocolCIDRs = []string{"10.0.0.0/33"} },
		"unknown header":           func(s *GlobalSettings) { s.RealIPHeader = "X-Client-IP" },
		"header injection":         func(s *GlobalSettings) { s.RealIPHeader = "X-Forwarded-For,1) }\n\thttp-request allow" },
	}
	for name, mutate := range cases {
		s := ok
		mutate(&s)
		if err := ValidateSettingsRenderSafety(&s); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
