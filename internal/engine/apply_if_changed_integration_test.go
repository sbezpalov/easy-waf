// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"fmt"
	"os"
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
