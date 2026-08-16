package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Every case here is a value that the API handler rejects but that could reach
// the row another way — a restored backup, a direct UPDATE, a future second
// write path. The renderer must refuse it on its own, because by the time these
// bytes are in a file `haproxy -c` will accept them.

func injectionInput() RenderInput {
	return RenderInput{
		Settings: goldenGlobalSettings("testdata/golden/spoe/minimal-spoe.cfg", "crowdsec"),
		Applications: []config.Application{
			{
				ID: "a1", Name: "App", PublicHost: "app.example.com",
				BackendHost: "10.0.0.9", BackendPort: 443,
				Profile: "balanced", CertificateID: "c1", Enabled: true,
			},
		},
		Certificates: map[string]config.Certificate{
			"c1": {ID: "c1", BundlePath: "testdata/golden/certs/bundle-a.pem"},
		},
		CRTListPath: "testdata/golden/injection.crt-list.txt",
	}
}

func TestRenderRejectsBackendTLSCAFileInjection(t *testing.T) {
	// backendTLSOptions Sprintf's this straight into the `server` line, so a
	// newline adds directives to the backend: another server, a header, or
	// `verify none` on the connection this field exists to protect.
	in := injectionInput()
	in.Applications[0].BackendHTTPS = true
	in.Applications[0].BackendTLSVerify = config.BackendTLSVerifyRequired
	in.Applications[0].BackendTLSCAFile = "/etc/ssl/certs/ca-certificates.crt\n    http-request set-header X-Injected 1\n    server evil 10.9.9.9:80 #"

	r, err := Render(in)
	if err == nil {
		t.Fatalf("render accepted an injected ca-file; config contained:\n%s", r.HAProxyConfig)
	}
	if !strings.Contains(err.Error(), "backend_tls_ca_file") {
		t.Errorf("error does not name the field: %v", err)
	}

	// A space is enough on its own: `ca-file /a b` makes b the next token.
	in.Applications[0].BackendTLSCAFile = "/etc/ssl/certs/ca.crt verify none"
	if _, err := Render(in); err == nil {
		t.Error("render accepted a ca-file containing a space")
	}
}

func TestRenderRejectsCertificatePathInjection(t *testing.T) {
	// A crt-list is one entry per line and an entry may carry an SNI filter, so
	// a newline plus `*` takes over certificate selection for every vhost.
	for name, cert := range map[string]config.Certificate{
		"newline in bundle_path": {
			ID:         "c1",
			BundlePath: "testdata/golden/certs/bundle-a.pem\n/tmp/evil.pem *",
		},
		"newline in pem_crt_path": {
			ID:         "c1",
			BundlePath: "testdata/golden/certs/bundle-a.pem",
			PEMCrtPath: "/tmp/ok.pem\n/tmp/evil.pem *",
		},
		"crt-list options": {
			ID:         "c1",
			BundlePath: "testdata/golden/certs/bundle-a.pem [verify optional]",
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := injectionInput()
			in.Certificates["c1"] = cert
			r, err := Render(in)
			if err == nil {
				t.Fatalf("render accepted it; crt-list was:\n%s", r.CRTList)
			}
			if !strings.Contains(err.Error(), "certificate") {
				t.Errorf("error does not mention the certificate: %v", err)
			}
		})
	}
}

func TestRenderRejectsSettingsInjection(t *testing.T) {
	// crowdsec_engine_name is rendered as `filter spoe engine <name>` and again
	// in send-spoe-group, so a newline plants a bare `http-request allow` that
	// short-circuits every deny after it.
	in := injectionInput()
	in.Applications[0].Security.CrowdSecEnabled = true
	in.Settings.CrowdSecEngineName = "cs\n    http-request allow"
	r, err := Render(in)
	if err == nil {
		t.Fatalf("render accepted an injected engine name; config contained:\n%s", r.HAProxyConfig)
	}
	if !strings.Contains(err.Error(), "crowdsec_engine_name") {
		t.Errorf("error does not name the field: %v", err)
	}

	in = injectionInput()
	in.Settings.IPBlacklistMapPath = "testdata/golden/ipbl/test.map\n    http-request allow"
	if _, err := Render(in); err == nil {
		t.Error("render accepted an injected map path")
	}
}

func TestRenderStillAcceptsRealisticPaths(t *testing.T) {
	// The character class has to stay wide enough for the paths an appliance
	// actually uses, including the relative ones the test fixtures rely on.
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/var/lib/easy-waf/certs/app.example.com/bundle.pem",
		"/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb",
		"/run/haproxy/easy-waf-admin.sock",
		"testdata/golden/certs/bundle-a.pem",
		"/opt/easy_waf/ca-2024.pem",
	} {
		if err := config.ValidateConfigFilePath("path", p, false); err != nil {
			t.Errorf("rejected a legitimate path %q: %v", p, err)
		}
	}
}

func TestPublicHostRejectsUppercaseAndUnderscore(t *testing.T) {
	// Both used to be accepted, and both were silent security failures rather
	// than cosmetic ones — see the comment on validHostnameRe.
	for _, host := range []string{"SHOP.example.com", "Shop.example.com", "a_b.example.com"} {
		in := injectionInput()
		in.Applications[0].PublicHost = host
		if _, err := Render(in); err == nil {
			t.Errorf("render accepted public_host %q", host)
		}
	}
	for _, host := range []string{"shop.example.com", "a-b.example.com", "ha.lan"} {
		in := injectionInput()
		in.Applications[0].PublicHost = host
		if _, err := Render(in); err != nil {
			t.Errorf("render rejected a legitimate public_host %q: %v", host, err)
		}
	}
}

func TestRenderNamesBothApplicationsOnIdentifierCollision(t *testing.T) {
	// The validator now rules out the two known ways to collide, so this is
	// exercised through the mapping directly: what matters is that the failure
	// says which rows are involved instead of leaving the operator with a
	// duplicate-proxy error from HAProxy and a wedged apply.
	apps := []config.Application{
		{ID: "one", PublicHost: "a.b.com", Enabled: true},
		{ID: "two", PublicHost: "a_b.com", Enabled: true},
	}
	err := checkIdentifierCollisions(apps)
	if err == nil {
		t.Fatal("collision not detected")
	}
	for _, want := range []string{"one", "two", "a.b.com", "a_b.com", "bk_a_b_com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if err := checkIdentifierCollisions([]config.Application{
		{ID: "one", PublicHost: "a.b.com", Enabled: true},
		{ID: "two", PublicHost: "c.d.com", Enabled: true},
		{ID: "three", PublicHost: "a.b.com", Enabled: false},
	}); err != nil {
		t.Errorf("false positive: %v", err)
	}
}
