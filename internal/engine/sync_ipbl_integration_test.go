// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/store"
)

// SyncIPBL honors what is stored, not this process's copy: external feeds
// switched off elsewhere (admin CLI, another instance) stop here too, and
// their saved copies are deleted so they cannot come back.
func TestSyncIPBL_UsesStoredSettingsAndDropsFeedCopies(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	state := t.TempDir()

	stored := config.DefaultSettings(state)
	stored.IPBLExternalEnabled = false
	stored.GeoIPEnabled = false
	e := engine.New(state, st, stored)
	useStoredSettingsForTest(t, st, e)

	// This process still believes feeds are on.
	inMemory := stored
	inMemory.IPBLExternalEnabled = true
	e.SetSettings(inMemory)

	copyPath := filepath.Join(ipbl.FeedCacheDir(state), "some-source.list")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := e.SyncIPBL(ctx); err != nil {
		t.Fatal(err)
	}
	if e.Settings().IPBLExternalEnabled {
		t.Fatal("SyncIPBL kept the stale in-memory settings")
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("feed copy kept with feeds off: %v", err)
	}
}
