// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/easy-waf/easy-waf/internal/engine"
)

// applyEdgeCLI re-renders HAProxy config from the database and reloads haproxy (same path as POST /api/v1/apply).
// Run as root on the appliance after template upgrades or before first haproxy start with the state-dir drop-in.
func applyEdgeCLI() {
	if err := runApplyEdge(); err != nil {
		log.Fatal(err)
	}
}

func runApplyEdge() error {
	fs := flag.NewFlagSet("apply-edge", flag.ExitOnError)
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env (DATABASE_URL)")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory (EASY_WAF_STATE_DIR)")
	databaseURL := fs.String("database-url", "", "optional: postgres DSN (overrides DATABASE_URL from env file / environment)")
	label := fs.String("label", "easy-waf-admin-apply-edge", "revision label stored in config_revisions")
	_ = fs.Parse(os.Args[2:])

	ctx := context.Background()
	st, err := openStoreFromEnvFile(*envFile, *databaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	eng := &engine.Engine{StateDir: *stateDir, Store: st}
	if err := eng.LoadSettings(ctx); err != nil {
		return err
	}
	if err := eng.Apply(ctx, *label); err != nil {
		return err
	}
	if os.Getenv("EASY_WAF_SKIP_RELOAD") != "" {
		log.Print("apply-edge: HAProxy config written from database (reload skipped; EASY_WAF_SKIP_RELOAD set)")
		return nil
	}
	log.Print("apply-edge: HAProxy config written from database and service reloaded")
	return nil
}
