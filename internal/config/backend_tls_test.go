package config

import (
	"path/filepath"
	"testing"
)

func TestValidateBackendCAFile(t *testing.T) {
	state := "/var/lib/easy-waf"
	if err := ValidateBackendCAFile(state, DefaultSystemCABundle); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackendCAFile(state, "/etc/easy-waf/ca/lab.pem"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackendCAFile(state, filepath.Join(state, "ca", "app.crt")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackendCAFile(state, "/etc/easy-waf/ca/../passwd"); err == nil {
		t.Fatal("traversal must be rejected")
	}
	if err := ValidateBackendCAFile(state, "/tmp/evil.pem"); err == nil {
		t.Fatal("non-allowlisted path must be rejected")
	}
	if err := ValidateBackendCAFile(state, "relative.pem"); err == nil {
		t.Fatal("relative path must be rejected")
	}
}

func TestNormalizeBackendTLS(t *testing.T) {
	a := Application{BackendHTTPS: true}
	NormalizeBackendTLS(&a)
	if a.BackendTLSVerify != BackendTLSVerifyRequired {
		t.Fatalf("default %q", a.BackendTLSVerify)
	}
	a.BackendTLSVerify = "none"
	NormalizeBackendTLS(&a)
	if !BackendTLSInsecure(a) {
		t.Fatal("expected insecure")
	}
}
