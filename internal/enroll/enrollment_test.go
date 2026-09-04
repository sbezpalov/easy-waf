// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentFile_roundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Fatalf("len=%d", len(secret))
	}
	path, err := WriteFile(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	got, err := ReadFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatal("secret mismatch")
	}
	hash := HashSecret(secret)
	if !SecretEqual(secret, hash) {
		t.Fatal("hash compare")
	}
	if SecretEqual("deadbeef", hash) {
		t.Fatal("wrong secret must not match")
	}
	if err := RemoveFile(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "enrollment")); !os.IsNotExist(err) {
		t.Fatal("expected removal")
	}
}
