package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestBackendHostIsLiteralIP(t *testing.T) {
	if !backendHostIsLiteralIP("10.0.0.1") {
		t.Fatal("IP expected")
	}
	if !backendHostIsLiteralIP("192.168.1.5") {
		t.Fatal("IP expected")
	}
	if backendHostIsLiteralIP("nas.lan") {
		t.Fatal("FQDN must not be literal IP")
	}
	if backendHostIsLiteralIP("app.example.com") {
		t.Fatal("FQDN must not be literal IP")
	}
}

func TestRenderBackendHostnameResolvers(t *testing.T) {
	in := RenderInput{
		Settings: goldenGlobalSettings("testdata/golden/spoe/minimal-spoe.cfg", "crowdsec"),
		Applications: []config.Application{
			{
				ID: "h1", Name: "NAS", PublicHost: "nas.example.com",
				BackendHost: "nas.lan", BackendPort: 8080,
				Profile: "balanced", CertificateID: "c1", Enabled: true,
			},
		},
		Certificates: map[string]config.Certificate{
			"c1": {ID: "c1", BundlePath: "testdata/golden/certs/bundle-a.pem"},
		},
		CRTListPath: "testdata/golden/backend-by-hostname.crt-list.txt",
	}
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.HAProxyConfig, "resolvers easy_waf_dns") {
		t.Error("expected resolvers section")
	}
	if !strings.Contains(r.HAProxyConfig, "init-addr last,libc,none") {
		t.Error("expected init-addr for DNS backend")
	}
}

func TestRenderBackendIPNoResolvers(t *testing.T) {
	in := RenderInput{
		Settings: goldenGlobalSettings("testdata/golden/spoe/minimal-spoe.cfg", "crowdsec"),
		Applications: []config.Application{
			{
				ID: "ip1", Name: "IP", PublicHost: "ip.example.com",
				BackendHost: "10.0.0.9", BackendPort: 80,
				Profile: "balanced", CertificateID: "c1", Enabled: true,
			},
		},
		Certificates: map[string]config.Certificate{
			"c1": {ID: "c1", BundlePath: "testdata/golden/certs/bundle-a.pem"},
		},
		CRTListPath: "testdata/golden/backend-by-ip.crt-list.txt",
	}
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.HAProxyConfig, "resolvers easy_waf_dns") {
		t.Error("IP backend must not add resolvers section")
	}
	if strings.Contains(r.HAProxyConfig, "init-addr") {
		t.Error("IP backend must not use init-addr")
	}
}
