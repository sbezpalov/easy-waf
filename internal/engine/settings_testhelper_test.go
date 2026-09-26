// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"os"
	"testing"

	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

// useStoredSettingsForTest persists e's settings (Apply re-reads them from the
// database) and puts back whatever was stored before when the test ends, so
// later tests do not inherit this test's temporary paths. It restores through
// its own connection: tests often close theirs with defer, which runs before
// t.Cleanup.
func useStoredSettingsForTest(t *testing.T, st *store.Store, e *engine.Engine) {
	t.Helper()
	ctx := context.Background()
	const key = "global_settings_json"
	prev, err := st.GetSetting(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SaveSettings(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		restore, err := store.OpenPostgresForDiagnostics(os.Getenv("DATABASE_URL"))
		if err != nil {
			t.Errorf("restore settings: %v", err)
			return
		}
		defer restore.Close()
		if prev == "" {
			err = restore.DeleteSetting(context.Background(), key)
		} else {
			err = restore.SetSetting(context.Background(), key, prev)
		}
		if err != nil {
			t.Errorf("restore settings: %v", err)
		}
	})
}
