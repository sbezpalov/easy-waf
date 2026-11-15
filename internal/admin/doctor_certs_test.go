// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCertificatesWarnsWhenFullchainIsMissingOrInvalid(t *testing.T) {
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "certs", "missing"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "certs", "garbage"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "certs", "garbage", "fullchain.pem"), []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := checkCertificates(state)
	if len(checks) != 2 {
		t.Fatalf("got %d checks, want one warning per broken directory: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Status != StatusWarn {
			t.Fatalf("status %q for %s, want WARN (%s)", c.Status, c.Name, c.Message)
		}
	}
}
