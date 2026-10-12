// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

func revisionCount(t *testing.T, st *store.Store) int {
	t.Helper()
	revs, err := st.ListConfigRevisions(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(revs)
}

func TestApplyIfChangedOnlyAppliesDifferences(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	ctx := context.Background()

	stateDir := t.TempDir()
	cfg := config.DefaultSettings(stateDir)
	cfg.IPBLExternalEnabled = false
	e := engine.New(stateDir, st, cfg)
	useStoredSettingsForTest(t, st, e)

	applied, err := e.ApplyIfChanged(ctx, "reconcile-test")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("first reconcile with no live config did not apply")
	}
	before := revisionCount(t, st)

	applied, err = e.ApplyIfChanged(ctx, "reconcile-test")
	if err != nil {
		t.Fatal(err)
	}
	if applied || revisionCount(t, st) != before {
		t.Fatal("reconcile applied (and recorded a revision) although nothing changed")
	}

	app := config.Application{
		Name:        fmt.Sprintf("reconcile%d", time.Now().UnixNano()),
		PublicHost:  fmt.Sprintf("reconcile%d.example.com", time.Now().UnixNano()),
		BackendHost: "10.0.0.7",
		BackendPort: 8080,
		Profile:     "balanced",
		ListenMode:  "http_only",
		Enabled:     true,
	}
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteApplication(context.Background(), app.ID) })

	applied, err = e.ApplyIfChanged(ctx, "reconcile-test")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("reconcile did not apply a new application")
	}
}

// A certificate renewed in place (same ID and paths, new PEM) changes no
// config or map file; ApplyIfChanged must still apply it, or HAProxy keeps
// serving the old certificate after an interrupted post-renewal apply.
func TestApplyIfChangedAppliesRenewedCertificate(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	ctx := context.Background()

	stateDir := t.TempDir()
	cfg := config.DefaultSettings(stateDir)
	cfg.IPBLExternalEnabled = false
	e := engine.New(stateDir, st, cfg)
	useStoredSettingsForTest(t, st, e)

	pemDir := t.TempDir()
	fullchain := filepath.Join(pemDir, "fullchain.pem")
	key := filepath.Join(pemDir, "privkey.pem")
	for path, body := range map[string]string{fullchain: "CERT v1\n", key: "KEY v1\n"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	suffix := time.Now().UnixNano()
	cert := config.Certificate{
		PrimaryDomain: fmt.Sprintf("renew%d.example.com", suffix),
		Mode:          "http-01",
		ACMEStatus:    "ready",
		FullchainPath: fullchain,
		PEMKeyPath:    key,
	}
	if err := st.UpsertCertificate(ctx, &cert); err != nil {
		t.Fatal(err)
	}
	app := config.Application{
		Name:          fmt.Sprintf("renew%d", suffix),
		PublicHost:    cert.PrimaryDomain,
		BackendHost:   "10.0.0.8",
		BackendPort:   8080,
		Profile:       "balanced",
		Enabled:       true,
		CertificateID: cert.ID,
	}
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = st.DeleteApplication(context.Background(), app.ID)
		_ = st.DeleteCertificate(context.Background(), cert.ID)
	})

	if _, err := e.ApplyIfChanged(ctx, "renew-test"); err != nil {
		t.Fatal(err)
	}
	if applied, err := e.ApplyIfChanged(ctx, "renew-test"); err != nil || applied {
		t.Fatalf("nothing changed, yet applied=%v err=%v", applied, err)
	}

	// Renewal: same files, new content (what acmed writes).
	if err := os.WriteFile(fullchain, []byte("CERT v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err := e.ApplyIfChanged(ctx, "renew-test")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("renewed certificate not applied")
	}
	if applied, err := e.ApplyIfChanged(ctx, "renew-test"); err != nil || applied {
		t.Fatalf("renewal applied twice: applied=%v err=%v", applied, err)
	}

	// Renewal whose apply fails (HAProxy rejects the config): the apply
	// rolls back the config, but the new PEM stays on disk. The next
	// reconcile must still apply it.
	if err := os.WriteFile(fullchain, []byte("CERT v3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "")
	bad := e.Settings()
	bad.HAProxyBinary = "/bin/false"
	e.SetSettings(bad)
	if err := e.SaveSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(ctx, "renew-test"); err == nil {
		t.Fatal("apply with /bin/false as haproxy succeeded")
	}
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	applied, err = e.ApplyIfChanged(ctx, "renew-test")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("certificate renewed before a failed apply was never applied")
	}
}
