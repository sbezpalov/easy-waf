// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/acme"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestMain(m *testing.M) {
	if child, code := issueChildEntry(); child {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestChildEntryDoesNotStartTheDatabaseWorker(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "")
	res, err := acme.IssueInProcess(t.Context(), executable, acme.IssueRequest{Email: "ops@example.test", Mode: "unsupported", Domains: []string{"example.test"}})
	if err == nil || res != nil || !strings.Contains(err.Error(), "unsupported ACME challenge mode") || strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatal("child command entered the parent database loop or accepted an invalid challenge")
	}
}

func writeLegacyApplyPending(t *testing.T, state string) {
	t.Helper()
	path := applyPendingPath(state)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("legacy cert-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func legacyPendingForTest(t *testing.T, state string) bool {
	t.Helper()
	pending, err := applyPending(state)
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

func TestLegacyApplyPendingMark(t *testing.T) {
	state := t.TempDir()
	if legacyPendingForTest(t, state) {
		t.Fatal("pending before anything was stored")
	}
	writeLegacyApplyPending(t, state)
	if !legacyPendingForTest(t, state) {
		t.Fatal("mark not visible")
	}
	b, err := os.ReadFile(applyPendingPath(state))
	if err != nil || len(b) == 0 {
		t.Fatalf("mark content: %q %v", b, err)
	}
	if err := clearApplyPending(state); err != nil {
		t.Fatal(err)
	}
	if legacyPendingForTest(t, state) {
		t.Fatal("mark not cleared")
	}
	if err := clearApplyPending(state); err != nil {
		t.Fatal(err)
	} // clearing twice is fine
}

func TestLegacyMarkerErrorsStopBeforeDatabaseOrApply(t *testing.T) {
	for _, kind := range []string{"directory", "invalid-path"} {
		t.Run(kind, func(t *testing.T) {
			state := t.TempDir()
			if kind == "directory" {
				if err := os.MkdirAll(applyPendingPath(state), 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				state = filepath.Join(state, "invalid\x00path")
			}
			if pending, err := applyPending(state); pending || err == nil {
				t.Fatal("invalid marker was accepted or hidden as absent")
			}
			eng := engine.New(state, nil, config.DefaultSettings(state))
			if applied, err := reconcileCertificateApplies(t.Context(), eng, "acme-test"); applied || err == nil {
				t.Fatal("invalid marker did not prevent reconciliation")
			}
		})
	}
	state := t.TempDir()
	path := applyPendingPath(state)
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := clearApplyPending(state); err == nil {
		t.Fatal("cleanup failure was hidden")
	}
}

func TestLegacyMarkerPermissionAndSymlinkErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions and unprivileged symlinks")
	}
	state := t.TempDir()
	writeLegacyApplyPending(t, state)
	dir := filepath.Dir(applyPendingPath(state))
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if pending, err := applyPending(state); pending || err == nil {
		t.Fatal("unreadable marker hidden as absent")
	}
	eng := engine.New(state, nil, config.DefaultSettings(state))
	if applied, err := reconcileCertificateApplies(t.Context(), eng, "acme-test"); applied || err == nil {
		t.Fatal("unreadable marker allowed reconciliation")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := clearApplyPending(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(state, "missing-target"), applyPendingPath(state)); err != nil {
		t.Fatal(err)
	}
	if pending, err := applyPending(state); pending || err == nil {
		t.Fatal("dangling symlink hidden as absent")
	}
}

// reconcile must not query/apply while backing off or
// with applies disabled. The engine has no store, so an Apply would panic.
func TestReconcileOnlyWhenPending(t *testing.T) {
	state := t.TempDir()
	w := &worker{eng: engine.New(state, nil, config.DefaultSettings(state))}
	ctx := context.Background()

	mustNotApply := func(name string) {
		t.Helper()
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s: reconcile tried to apply: %v", name, p)
			}
		}()
		w.reconcile(ctx)
	}

	writeLegacyApplyPending(t, state)
	w.lastTry = time.Now()
	mustNotApply("within the retry backoff")

	w.lastTry = time.Time{}
	t.Setenv("EASY_WAF_ACME_SKIP_APPLY", "1")
	mustNotApply("applies disabled")
	if !legacyPendingForTest(t, state) {
		t.Fatal("mark dropped without a successful apply")
	}
}

func TestCertificateWarningsNameTheCertificateAndTheCause(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	soon, later := now.Add(10*24*time.Hour), now.Add(80*24*time.Hour)

	lines := certificateWarnings([]config.Certificate{
		{PrimaryDomain: "fine.example", ACMEStatus: "ready", NotAfter: &later},
		{PrimaryDomain: "soon.example", ACMEStatus: "ready", NotAfter: &soon},
		{PrimaryDomain: "failed.example", ACMEStatus: "failed", NotAfter: &later, LastError: "dns\ntimeout"},
	}, now)

	if len(lines) != 2 {
		t.Fatalf("lines %q", lines)
	}
	if !strings.Contains(lines[0], `"soon.example"`) || !strings.Contains(lines[0], "expires in 10 days") {
		t.Fatalf("line %q", lines[0])
	}
	if !strings.Contains(lines[1], "renewal failed") || !strings.Contains(lines[1], `dns\ntimeout`) {
		t.Fatalf("line %q", lines[1])
	}
	// A stored error must not be able to forge journal lines.
	if strings.Contains(lines[1], "\n") {
		t.Fatalf("raw newline in %q", lines[1])
	}
}

func TestCertificateWarningsQuietWhenAllIsWell(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	later := now.Add(80 * 24 * time.Hour)

	lines := certificateWarnings([]config.Certificate{{PrimaryDomain: "fine.example", ACMEStatus: "ready", NotAfter: &later}}, now)

	if len(lines) != 0 {
		t.Fatalf("lines %q", lines)
	}
}
