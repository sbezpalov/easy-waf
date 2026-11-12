// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSupportBundleGzip_nilStore(t *testing.T) {
	_, err := BuildSupportBundleGzip(context.Background(), Params{})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestManagedHAProxyConfigPath(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.WriteFile(inside, []byte("global\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := managedHAProxyConfigPath(stateDir, inside)
	want, resolveErr := filepath.EvalSymlinks(inside)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if err != nil || got != want {
		t.Fatalf("got %q err %v", got, err)
	}
	missing := filepath.Join(managedDir, "missing.cfg")
	if got, err := managedHAProxyConfigPath(stateDir, missing); err != nil || got != missing {
		t.Fatalf("missing managed path: got %q err %v", got, err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, "/etc/passwd"); err == nil {
		t.Fatal("expected path outside state directory to fail")
	}
}

func TestManagedHAProxyConfigPathRejectsEscapingSymlink(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.cfg")
	if err := os.WriteFile(outside, []byte("global\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, link); err == nil {
		t.Fatal("expected escaping symlink to fail")
	}
}

func TestManagedHAProxyConfigPathRejectsDanglingSymlink(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.cfg"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, link); err == nil {
		t.Fatal("expected dangling symlink to fail closed")
	}
}

func TestProcessEnvSnapshotMasksSecretsAndSkipsOtherVariables(t *testing.T) {
	t.Setenv("EASY_WAF_LISTEN_HTTPS", "0.0.0.0:8443")
	t.Setenv("EASY_WAF_ADMIN_TOKEN", "super-secret-token")
	t.Setenv("DATABASE_URL", "postgres://easywaf:db-password@127.0.0.1:5432/easywaf")
	t.Setenv("UNRELATED_SECRET_VALUE", "must-not-appear")

	out := string(MaskEasyWAFEnvContent(processEnvSnapshot("/etc/easy-waf/easy-waf.env", errors.New("permission denied"))))

	if !strings.Contains(out, "EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443") {
		t.Errorf("settings missing:\n%s", out)
	}
	for _, leaked := range []string{"super-secret-token", "db-password", "must-not-appear"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q leaked:\n%s", leaked, out)
		}
	}
}
