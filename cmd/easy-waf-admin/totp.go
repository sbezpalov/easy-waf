// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

// disableTOTPCLI is the console way back in when a phone and its recovery codes are lost.
func disableTOTPCLI() {
	fs := flag.NewFlagSet("disable-totp", flag.ExitOnError)
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env")
	dbURL := fs.String("database-url", "", "PostgreSQL URL (default: from env file)")
	user := fs.String("user", "", "panel username")
	_ = fs.Parse(os.Args[2:])
	if *user == "" {
		log.Fatal("-user is required")
	}
	st, err := openStoreFromEnvFile(*envFile, *dbURL)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	err = st.DisableTOTP(ctx, *user)
	if err == nil {
		_ = st.AppendAudit(ctx, "panel_user_totp_reset", map[string]any{"username": *user, "via": "easy-waf-admin"})
	}
	_ = st.Close()
	if err != nil {
		log.Fatalf("disable two-factor sign-in for %q: %v", *user, err)
	}
	fmt.Printf("two-factor sign-in turned off for %s\n", *user)
}
