// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestMain(m *testing.M) {
	if os.Getenv("EASY_WAF_ENGINE_RELOAD_TEST") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestApplyBookkeepingFailureReportsKeptConfiguration(t *testing.T) {
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
	installSuccessfulReloadFixture(t)
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	for _, tc := range []struct {
		name          string
		skipReload    bool
		onlyIfChanged bool
	}{
		{"apply", false, false},
		{"if-changed", false, true},
		{"skip-reload-apply", true, false},
		{"skip-reload-if-changed", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EASY_WAF_SKIP_RELOAD", "0")
			if tc.skipReload {
				t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
			}
			ctx := t.Context()
			stateDir := t.TempDir()
			cfg := config.DefaultSettings(stateDir)
			cfg.IPBLExternalEnabled = false
			e := engine.New(stateDir, st, cfg)
			useStoredSettingsForTest(t, st, e)
			cfgPath := haproxy.LiveCfgPath(stateDir, cfg.HAProxyConfigPath)
			var app config.Application
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if app.ID != "" {
					if err := st.DeleteApplication(ctx, app.ID); err != nil {
						t.Errorf("clean application: %v", err)
					}
				}
				if _, err := db.ExecContext(ctx, `DELETE FROM config_revisions WHERE left(content_path, length($1)) = $1`, stateDir+string(filepath.Separator)); err != nil {
					t.Errorf("clean revisions: %v", err)
				}
				if _, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE detail_json->>'path' = $1`, cfgPath); err != nil {
					t.Errorf("clean audit: %v", err)
				}
			})
			if err := e.Apply(ctx, "outcome-baseline"); err != nil {
				t.Fatal(err)
			}
			baseline, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("outcome-%d", time.Now().UnixNano())
			app = config.Application{Name: name, PublicHost: name + ".example", BackendHost: "127.0.0.1", BackendPort: 8080, ListenMode: "http_only", Profile: "balanced", Enabled: true}
			if err := st.UpsertApplication(ctx, &app); err != nil {
				t.Fatal(err)
			}
			// PostgreSQL rejects NUL in text. The label is first persisted after
			// reload, so this injects a bookkeeping failure without schema changes.
			label := "outcome-bookkeeping\x00failure"
			if tc.onlyIfChanged {
				var applied bool
				applied, err = e.ApplyIfChanged(ctx, label)
				if applied == tc.skipReload {
					t.Fatalf("applied=%v after failed bookkeeping, skipReload=%v", applied, tc.skipReload)
				}
			} else {
				err = e.Apply(ctx, label)
			}
			var appliedErr *engine.AppliedError
			if err == nil || errors.As(err, &appliedErr) == tc.skipReload || !strings.Contains(err.Error(), "record HAProxy revision and audit") {
				t.Fatalf("incorrect outcome after bookkeeping failure, skipReload=%v: %v", tc.skipReload, err)
			}
			live, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if tc.skipReload {
				if !bytes.Equal(live, baseline) {
					t.Fatal("skip-reload bookkeeping failure did not restore artifacts")
				}
			} else if !bytes.Contains(live, []byte(app.PublicHost)) {
				t.Fatal("bookkeeping failure reverted an already loaded configuration")
			}
		})
	}
}

func installSuccessfulReloadFixture(t *testing.T) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "systemctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), program, 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture replaces systemctl.
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_ENGINE_RELOAD_TEST", "1")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
