package config

import (
	"strings"
	"testing"
)

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
