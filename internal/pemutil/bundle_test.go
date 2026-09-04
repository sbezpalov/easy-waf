// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package pemutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBundle(t *testing.T) {
	dir := t.TempDir()
	fullchainPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	destPath := filepath.Join(dir, "bundle.pem")

	chainData := []byte("CERTIFICATE DATA\n")
	keyData := []byte("PRIVATE KEY DATA\n")

	if err := os.WriteFile(fullchainPath, chainData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteBundle(destPath, fullchainPath, keyPath, 0o600); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile destPath failed: %v", err)
	}

	want := string(chainData) + string(keyData)
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}
