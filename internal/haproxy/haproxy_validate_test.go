// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/config"
)

// TestRenderedConfigPassesHaproxyCheck writes a realistic rendered config and PEM material,
// comments the CrowdSec SPOE filter (vendor SPOE/Lua not present in CI), and requires
// `haproxy -c` to succeed. Skips when haproxy is not installed.
func TestRenderedConfigPassesHaproxyCheck(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH (install the haproxy package to run this check)")
	}

	dir := t.TempDir()
	hdir := filepath.Join(dir, "haproxy")
	if err := os.MkdirAll(hdir, 0o750); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(hdir, "bundle.pem")
	if err := writeSelfSignedBundle(bundle); err != nil {
		t.Fatal(err)
	}

	// The real vendor file: this test is what proves the generated config and
	// the bouncer agree on the group, the backend and the engine.
	spoePath, err := filepath.Abs(filepath.Join("testdata", "golden", "spoe", "crowdsec-vendor.cfg"))
	if err != nil {
		t.Fatal(err)
	}

	st := config.DefaultSettings(dir)
	st.SPOEConfigPath = spoePath
	st.CrowdSecEngineName = "crowdsec"
	st.ListenIPv6 = true
	st.TrustedProxyCIDRs = []string{"173.245.48.0/20", "2400:cb00::/32"}
	st.ProxyProtocolCIDRs = []string{"192.168.88.1"}
	st.TCPServices = []config.TCPService{
		{Name: "mqtt", ListenPort: 8883, BackendHost: "127.0.0.1", BackendPort: 1883, AllowCIDRs: []string{"192.168.0.0/16"}, Enabled: true},
		{Name: "rtsp", ListenPort: 8554, BackendHost: "frigate.lan", BackendPort: 8554, Enabled: true},
	}

	crtListPath := filepath.Join(hdir, "crt-list.txt")
	in := RenderInput{
		Settings: st,
		Applications: []config.Application{
			{
				ID:            "a1",
				Name:          "Test",
				PublicHost:    "app.example.com",
				BackendHost:   "127.0.0.1",
				BackendPort:   8080,
				Profile:       "balanced",
				CertificateID: "c1",
				Enabled:       true,
			},
			{
				ID: "a2", Name: "Failover in maintenance", PublicHost: "down.example.com", BackendHost: "127.0.0.1", BackendPort: 8081,
				BackendBalance: "source", BackendServers: []config.BackendServer{{Host: "127.0.0.2", Port: 8081, Backup: true}},
				Maintenance: true, MaintenanceBypassCIDRs: []string{"192.168.1.0/24", "fd00::1"},
				Profile: "balanced", CertificateID: "c1", Enabled: true,
			},
		},
		Certificates: map[string]config.Certificate{
			"c1": {ID: "c1", BundlePath: bundle},
		},
		CRTListPath: crtListPath,
	}

	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	// Regression guard: older template used `(\.\./|\.\.[\\])` which HAProxy turns into invalid PCRE `[\]`.
	// If this fails on CI, the job is building a commit without the fixed traversal ACL in render.go.
	if strings.Contains(r.HAProxyConfig, "_traversal path -m reg") {
		const wantTraversalACL = `_traversal path -m reg -i \.\./`
		if !strings.Contains(r.HAProxyConfig, wantTraversalACL) {
			snippet := r.HAProxyConfig
			if i := strings.Index(r.HAProxyConfig, "_traversal path"); i >= 0 {
				snippet = r.HAProxyConfig[i:]
			}
			if len(snippet) > 200 {
				snippet = snippet[:200] + "…"
			}
			t.Fatalf("expected %q in rendered config (re-run after merging latest internal/haproxy/render.go); got near: %q", wantTraversalACL, snippet)
		}
	}
	if err := os.WriteFile(crtListPath, []byte(r.CRTList), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(hdir, "haproxy.cfg")
	if err := os.WriteFile(cfgPath, []byte(r.HAProxyConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := apply.Validate(hx, cfgPath); err != nil {
		t.Fatal(err)
	}
}

func writeSelfSignedBundle(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"easy-waf-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"app.example.com"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
