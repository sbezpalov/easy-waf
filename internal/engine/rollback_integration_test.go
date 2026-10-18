// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/store"
)

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestRollbackRestoresPriorConfig seeds two revision rows + snapshots, sets live cfg to the second,
// rolls back to the first, and asserts the live file matches the first snapshot. Requires PostgreSQL
// (DATABASE_URL). Skips when unset so CI without a DB still passes.
func TestRollbackRestoresPriorConfig(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")

	ctx := context.Background()
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Rollback resolves the live config path from the stored settings, so the
	// test stores its own. Loading whatever another test left there pointed
	// the rollback at that test's directory, and a rerun on the same database
	// failed ("already using this configuration", or v2 still live here).
	stateDir := t.TempDir()
	e := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	useStoredSettingsForTest(t, st, e)
	cfgPath := haproxy.LiveCfgPath(stateDir, e.Settings().HAProxyConfigPath)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o750); err != nil {
		t.Fatal(err)
	}

	cfgV1 := []byte("haproxy cfg revision v1 unique")
	cfgV2 := []byte("haproxy cfg revision v2 unique")
	h1 := shaHex(cfgV1)
	h2 := shaHex(cfgV2)

	revDir := filepath.Join(stateDir, "revisions")
	if err := os.MkdirAll(revDir, 0o750); err != nil {
		t.Fatal(err)
	}
	snap1 := filepath.Join(revDir, fmt.Sprintf("haproxy-%s.cfg", h1[:12]))
	snap2 := filepath.Join(revDir, fmt.Sprintf("haproxy-%s.cfg", h2[:12]))
	if err := os.WriteFile(snap1, cfgV1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snap2, cfgV2, 0o600); err != nil {
		t.Fatal(err)
	}

	var id1, id2 int64
	if err := db.QueryRowContext(ctx, `
		INSERT INTO config_revisions(at, label, haproxy_sha256, content_path) VALUES ($1,$2,$3,$4) RETURNING id`,
		time.Now().UTC(), "apply1", h1, cfgPath).Scan(&id1); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO config_revisions(at, label, haproxy_sha256, content_path) VALUES ($1,$2,$3,$4) RETURNING id`,
		time.Now().UTC(), "apply2", h2, cfgPath).Scan(&id2); err != nil {
		t.Fatal(err)
	}

	// The rollback adds a revision of its own. Remove it by what it is rather
	// than by an id read at the end of the test, so a failing run does not
	// leave it behind for the next one.
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx2,
			`DELETE FROM config_revisions WHERE id IN ($1, $2) OR (id > $2 AND label = $3)`,
			id1, id2, "rollback from "+h1[:12])
	})

	if err := os.WriteFile(cfgPath, cfgV2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Rollback(ctx, id1); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(cfgV1) {
		t.Fatalf("live config after rollback = %q, want v1", string(got))
	}

	latest, err := st.ListConfigRevisions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) == 0 {
		t.Fatal("expected new revision after rollback")
	}
	if !strings.HasPrefix(latest[0].Label, "rollback from ") {
		t.Fatalf("latest label = %q", latest[0].Label)
	}
	if latest[0].HAProxySHA256 != h1 {
		t.Fatalf("latest revision sha = %q, want %q", latest[0].HAProxySHA256, h1)
	}
}
