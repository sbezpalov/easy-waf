// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadJWTSecretRejectsShortFile(t *testing.T) {
	t.Setenv("EASY_WAF_JWT_SECRET", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "secrets", "jwt.secret")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tooshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadJWTSecret(dir)
	if err == nil {
		t.Fatal("expected short jwt.secret to fail closed")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Fatalf("error: %v", err)
	}
}

func TestLoadJWTSecretAcceptsLongFile(t *testing.T) {
	t.Setenv("EASY_WAF_JWT_SECRET", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "secrets", "jwt.secret")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("a", MinJWTSecretLen)
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadJWTSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("got %q", got)
	}
}

func TestLoadJWTSecretGeneratesWhenMissing(t *testing.T) {
	t.Setenv("EASY_WAF_JWT_SECRET", "")
	dir := t.TempDir()
	got, err := LoadJWTSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < MinJWTSecretLen {
		t.Fatalf("generated secret too short: %d", len(got))
	}
}
