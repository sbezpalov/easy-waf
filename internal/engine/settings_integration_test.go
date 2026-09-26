// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"os"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

// The API used to merge a settings PATCH over the copy it loaded at startup,
// writing back stale values for anything the admin CLI changed since.
func TestUpdateSettingsKeepsChangeMadeByAnotherProcess(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	stateDir := t.TempDir()

	api := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	useStoredSettingsForTest(t, st, api)

	// Another process (easy-waf-admin) changes the management CIDRs.
	cli := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	if _, err := cli.UpdateSettings(ctx, func(gs config.GlobalSettings) (config.GlobalSettings, error) {
		gs.ManagementAllowedCIDRs = []string{"10.9.8.0/24"}
		return gs, nil
	}); err != nil {
		t.Fatal(err)
	}

	// The API, still holding its startup copy, patches an unrelated field.
	got, err := api.UpdateSettings(ctx, func(gs config.GlobalSettings) (config.GlobalSettings, error) {
		gs.ACMEEmail = "ops@example.com"
		return gs, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ManagementAllowedCIDRs) != 1 || got.ManagementAllowedCIDRs[0] != "10.9.8.0/24" {
		t.Fatalf("CLI change lost: %v", got.ManagementAllowedCIDRs)
	}
	if api.Settings().ACMEEmail != "ops@example.com" {
		t.Fatal("in-memory settings not updated")
	}
}
