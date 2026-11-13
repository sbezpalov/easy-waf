// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestRollbackAfterArtifactPathsChange(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	for _, scenario := range []string{"success", "validation-fails-existing-paths", "validation-fails-absent-paths"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
			t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
			stateDir := t.TempDir()
			settings := config.DefaultSettings(stateDir)
			settings.IPBLExternalEnabled = false
			e := engine.New(stateDir, st, settings)
			useStoredSettingsForTest(t, st, e)
			oldConfig := haproxy.LiveCfgPath(stateDir, settings.HAProxyConfigPath)
			oldMap := settings.IPBlacklistMapPath
			newConfig := filepath.ToSlash(filepath.Join(stateDir, "relocated", "haproxy.cfg"))
			newMap := filepath.ToSlash(filepath.Join(stateDir, "relocated", "ipbl.map"))
			t.Cleanup(func() {
				// Include rows created before a failure as well as successful rollbacks.
				prefix := stateDir + string(filepath.Separator)
				if _, err := db.ExecContext(ctx, `DELETE FROM config_revisions WHERE left(content_path, length($1)) = $1`, prefix); err != nil {
					t.Errorf("clean revisions: %v", err)
				}
				if _, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE detail_json->>'path' IN ($1, $2)`, oldConfig, haproxy.LiveCfgPath(stateDir, newConfig)); err != nil {
					t.Errorf("clean audit: %v", err)
				}
			})
			if err := e.Apply(ctx, "rollback-paths-baseline"); err != nil {
				t.Fatal(err)
			}
			revisions, err := st.ListConfigRevisions(ctx, 1)
			if err != nil || len(revisions) != 1 {
				t.Fatalf("baseline revision: %v %v", revisions, err)
			}
			read := func(path string) []byte {
				t.Helper()
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return body
			}
			write := func(path, body string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			baselineConfig, baselineMap := read(oldConfig), read(oldMap)
			write(newConfig, "current config")
			write(newMap, "current map")
			write(oldConfig, "historical path reused")
			write(oldMap, "historical map reused")
			if scenario == "validation-fails-absent-paths" {
				for _, path := range []string{oldConfig, oldMap} {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := e.UpdateSettings(ctx, func(gs config.GlobalSettings) (config.GlobalSettings, error) {
				gs.HAProxyConfigPath = newConfig
				gs.IPBlacklistMapPath = newMap
				gs.HAProxyBinary = filepath.ToSlash(filepath.Join(stateDir, "missing-haproxy"))
				return gs, nil
			}); err != nil {
				t.Fatal(err)
			}
			if scenario != "success" {
				t.Setenv("EASY_WAF_SKIP_VALIDATE", "0")
			}
			err = e.Rollback(ctx, revisions[0].ID)
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(read(newConfig), baselineConfig) || !bytes.Equal(read(oldMap), baselineMap) {
					t.Fatal("rollback did not restore the revision at its historical and current config paths")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "validation failed") {
				t.Fatalf("expected validation failure after restoring revision: %v", err)
			}
			if string(read(newConfig)) != "current config" || string(read(newMap)) != "current map" {
				t.Fatal("failed rollback did not restore current artifacts")
			}
			if scenario == "validation-fails-existing-paths" {
				if string(read(oldConfig)) != "historical path reused" || string(read(oldMap)) != "historical map reused" {
					t.Fatal("failed rollback overwrote pre-existing files at historical paths")
				}
			} else {
				for _, path := range []string{oldConfig, oldMap} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("failed rollback left an artifact created at %s: %v", path, err)
					}
				}
			}
		})
	}
}
