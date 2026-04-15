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
		t.Skip("haproxy not in PATH (install apt package haproxy to run this check)")
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

	spoePath := filepath.Join(dir, "crowdsec-spoe.cfg")
	if err := os.WriteFile(spoePath, []byte("# placeholder for SPOE (not loaded when filter is commented)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	st := config.DefaultSettings(dir)
	st.SPOEConfigPath = spoePath
	st.CrowdSecEngineName = "crowdsec"

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
	if err := os.WriteFile(crtListPath, []byte(r.CRTList), 0o640); err != nil {
		t.Fatal(err)
	}

	// SPOE agent file format depends on CrowdSec/haproxy integration; CI validates the rest of the template.
	cfgBody := strings.Replace(r.HAProxyConfig, "\n\tfilter spoe ", "\n\t# filter spoe ", 1)
	if cfgBody == r.HAProxyConfig && strings.Contains(r.HAProxyConfig, "filter spoe") {
		t.Fatal("could not comment SPOE filter line — update haproxy_validate_test.go if template indentation changed")
	}
	cfgPath := filepath.Join(hdir, "haproxy.cfg")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o640); err != nil {
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
	return os.WriteFile(path, buf.Bytes(), 0o640)
}
