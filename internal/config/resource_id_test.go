package config

import (
	"strings"
	"testing"
)

func TestValidateResourceID(t *testing.T) {
	for _, id := range []string{"c1", "cert-01", "audit_apply_cert_123", "A9"} {
		if err := ValidateResourceID("certificate", id); err != nil {
			t.Fatalf("%q: %v", id, err)
		}
	}
	for _, id := range []string{"", ".", "..", "../acme", "a/b", "a b", "a\nbackend evil"} {
		if err := ValidateResourceID("certificate", id); err == nil {
			t.Fatalf("%q: expected rejection", id)
		}
	}
	if err := ValidateResourceID("certificate", strings.Repeat("a", maxResourceIDLength+1)); err == nil {
		t.Fatal("expected overlong id rejection")
	}
}
