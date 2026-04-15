// easy-waf-admin — emergency maintenance (run as root on appliance).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/admin"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "reset-control-panel-access":
		resetControlPanelAccess()
	case "reset-appliance":
		resetAppliance()
	case "factory-reset":
		factoryReset()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin reset-control-panel-access [-env-file path] [-state-dir path]")
	fmt.Fprintln(os.Stderr, "      Resets management CIDR allowlist to defaults and binds API to loopback in env file.")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin reset-appliance [-state-dir path] -confirm RESET")
	fmt.Fprintln(os.Stderr, "      Factory reset: truncates DB config tables and clears generated state (preferred).")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin factory-reset [-state-dir path] -i-am-sure")
	fmt.Fprintln(os.Stderr, "      Same as reset-appliance (legacy flag name).")
	fmt.Fprintln(os.Stderr, "Environment: DATABASE_URL (required)")
}

func openStore() (*store.Store, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	return store.OpenPostgres(dsn)
}

func resetControlPanelAccess() {
	fs := flag.NewFlagSet("reset-control-panel-access", flag.ExitOnError)
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	_ = fs.Parse(os.Args[2:])

	st, err := openStore()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	eng := &engine.Engine{StateDir: *stateDir, Store: st}
	if err := eng.LoadSettings(ctx); err != nil {
		log.Fatalf("load settings: %v", err)
	}
	eng.Settings.ManagementAllowedCIDRs = config.DefaultManagementCIDRs()
	if err := eng.SaveSettings(ctx); err != nil {
		log.Fatalf("save settings: %v", err)
	}
	log.Print("reset management_allowed_cidrs to defaults in database")

	if err := admin.UpsertEnvKey(*envFile, "EASY_WAF_LISTEN_HTTP", "127.0.0.1:8000"); err != nil {
		log.Fatalf("update env file: %v", err)
	}
	if err := admin.UpsertEnvKey(*envFile, "EASY_WAF_LISTEN_HTTPS", "127.0.0.1:8443"); err != nil {
		log.Fatalf("update env file: %v", err)
	}
	_ = admin.RemoveEnvKey(*envFile, "EASY_WAF_LISTEN")
	log.Printf("set EASY_WAF_LISTEN_HTTP=127.0.0.1:8000 EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443 in %s", *envFile)
	log.Print("next: systemctl restart easy-waf-api.service")
	log.Print("optional: review firewalld — remove broad 8000/8443/tcp on public zone if present")
}

const resetConfirmToken = "RESET"

// wipeApplianceData truncates configuration tables and recreates empty state subdirectories.
func wipeApplianceData(ctx context.Context, st *store.Store, stateDir string) {
	if err := st.FactoryReset(ctx); err != nil {
		log.Fatalf("database factory reset: %v", err)
	}
	log.Print("truncated configuration tables")

	sub := []string{"haproxy", "revisions", "certs", "acme", "secrets"}
	for _, name := range sub {
		p := filepath.Join(stateDir, name)
		if err := os.RemoveAll(p); err != nil {
			log.Printf("warning: remove %s: %v", p, err)
			continue
		}
		if err := os.MkdirAll(p, 0o750); err != nil {
			log.Printf("warning: mkdir %s: %v", p, err)
		}
	}
	log.Printf("recreated empty state subdirs under %s", stateDir)
}

func logPostWipeHints() {
	log.Print("next: ensure DATABASE_URL in /etc/easy-waf/easy-waf.env matches PostgreSQL user password (see scripts/lib/db-password.sh if install rotated it)")
	log.Print("next: systemctl restart easy-waf-api easy-waf-acmed")
	log.Print("hint: first API start recreates default operator admin/admin — change password in the UI")
}

func resetAppliance() {
	fs := flag.NewFlagSet("reset-appliance", flag.ExitOnError)
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	confirm := fs.String("confirm", "", fmt.Sprintf("must be %q to erase all appliance configuration", resetConfirmToken))
	_ = fs.Parse(os.Args[2:])

	if *confirm != resetConfirmToken {
		log.Fatalf("refusing: pass -confirm %s to erase all appliance configuration (DB + state under %s)", resetConfirmToken, *stateDir)
	}

	st, err := openStore()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	wipeApplianceData(ctx, st, *stateDir)
	logPostWipeHints()
}

func factoryReset() {
	fs := flag.NewFlagSet("factory-reset", flag.ExitOnError)
	sure := fs.Bool("i-am-sure", false, "required to proceed (prefer: reset-appliance -confirm RESET)")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	_ = fs.Parse(os.Args[2:])

	if !*sure {
		log.Fatal("refusing: pass -i-am-sure to confirm full data wipe (or use: reset-appliance -confirm RESET)")
	}

	st, err := openStore()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	wipeApplianceData(ctx, st, *stateDir)
	logPostWipeHints()
}
