// easy-waf-admin — emergency maintenance (run as root on appliance).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
	case "management-config":
		managementConfig()
	case "reset-appliance":
		resetAppliance()
	case "factory-reset":
		factoryReset()
	case "apply-edge":
		applyEdgeCLI()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin reset-control-panel-access [-env-file path] [-state-dir path]")
	fmt.Fprintln(os.Stderr, "      Resets management CIDR allowlist to defaults and binds API to loopback in env file.")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin management-config [-env-file path] [-state-dir path] [-database-url URL]")
	fmt.Fprintln(os.Stderr, "      Prints management listen addresses (env) and GUI/API source CIDRs (database).")
	fmt.Fprintln(os.Stderr, "      Optional: -listen-loopback | -listen-lan | -listen-http ADDR -listen-https ADDR")
	fmt.Fprintln(os.Stderr, "                -management-cidrs '10.0.0.0/8,...' | -default-management-cidrs")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin reset-appliance [-state-dir path] [-env-file path] [-database-url URL] [-bootstrap-credentials] [-credentials-out path] -confirm RESET")
	fmt.Fprintln(os.Stderr, "      Factory reset: truncates DB config tables and clears generated state (preferred).")
	fmt.Fprintln(os.Stderr, "      -bootstrap-credentials (root): new random 19-char DB password + EASY_WAF_ADMIN_TOKEN, updates env file, then wipes; GUI stays admin/admin after API start.")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin factory-reset [-state-dir path] [-env-file path] [-database-url URL] [-bootstrap-credentials] [-credentials-out path] -i-am-sure")
	fmt.Fprintln(os.Stderr, "      Same as reset-appliance (legacy flag name).")
	fmt.Fprintln(os.Stderr, "  easy-waf-admin apply-edge [-env-file path] [-state-dir path] [-database-url URL] [-label text]")
	fmt.Fprintln(os.Stderr, "      Re-render HAProxy config from PostgreSQL and reload-or-start haproxy (root; same as API POST /apply).")
	fmt.Fprintln(os.Stderr, "Environment: DATABASE_URL (required unless -database-url is passed or readable from -env-file; management-config reads -env-file by default)")
}

// openStoreFrom connects using url when non-empty; otherwise DATABASE_URL from the environment.
func openStoreFrom(url string) (*store.Store, error) {
	dsn := strings.TrimSpace(url)
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is required (export it or pass -database-url)")
	}
	return store.OpenPostgres(dsn)
}

func openStore() (*store.Store, error) {
	return openStoreFrom("")
}

func resolveDSNForWipe(envFile, databaseURL string) (string, error) {
	if strings.TrimSpace(databaseURL) != "" {
		return strings.TrimSpace(databaseURL), nil
	}
	v, err := admin.ReadEnvKey(envFile, "DATABASE_URL")
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", envFile, err)
	}
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), nil
	}
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("DATABASE_URL not set: use -database-url, put DATABASE_URL in %s, or export it", envFile)
}

// performBootstrapAndWipe rotates the PostgreSQL role password and EASY_WAF_ADMIN_TOKEN, writes env file, then wipes appliance tables/state.
func performBootstrapAndWipe(ctx context.Context, envFile, stateDir, credOut, databaseURL string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("bootstrap-credentials requires root (run with sudo)")
	}
	dsnIn, err := resolveDSNForWipe(envFile, databaseURL)
	if err != nil {
		return err
	}
	parts, err := admin.ParsePostgresURL(dsnIn)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	h := strings.ToLower(parts.Host)
	if h != "" && h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return fmt.Errorf("bootstrap-credentials only supports PostgreSQL on this host (127.0.0.1/localhost); got %q — rotate the role on the remote server manually, then use reset without -bootstrap-credentials", parts.Host)
	}
	dbPass, err := admin.RandomAlphanumericPassword(19)
	if err != nil {
		return err
	}
	adminTok, err := admin.RandomAlphanumericPassword(19)
	if err != nil {
		return err
	}
	if err := admin.AlterPostgresRolePassword(parts.User, dbPass); err != nil {
		return fmt.Errorf("postgres ALTER USER: %w", err)
	}
	newDSN := admin.BuildPostgresURL(parts.User, dbPass, parts)
	if err := admin.UpsertEnvKey(envFile, "DATABASE_URL", newDSN); err != nil {
		return fmt.Errorf("write DATABASE_URL to %s: %w", envFile, err)
	}
	if err := admin.UpsertEnvKey(envFile, "EASY_WAF_ADMIN_TOKEN", adminTok); err != nil {
		return fmt.Errorf("write EASY_WAF_ADMIN_TOKEN to %s: %w", envFile, err)
	}
	st, err := store.OpenPostgres(newDSN)
	if err != nil {
		return fmt.Errorf("connect with new DATABASE_URL: %w", err)
	}
	defer st.Close()
	wipeApplianceData(ctx, st, stateDir)
	report := fmt.Sprintf(`easy-waf automated bootstrap — %s

DATABASE_URL=%s
EASY_WAF_ADMIN_TOKEN=%s

GUI operator (after easy-waf-api starts): username admin / password admin — change immediately in the UI.

Delete this file after copying secrets to your vault.
`, time.Now().UTC().Format(time.RFC3339), newDSN, adminTok)
	if err := admin.WriteBootstrapReport(credOut, report); err != nil {
		return fmt.Errorf("write credentials report: %w", err)
	}
	return nil
}

func logPostBootstrapHints(credPath string) {
	if credPath == "" {
		credPath = admin.DefaultBootstrapReportPath
	}
	log.Printf("credentials written to %s (mode 0600) — copy to your vault, then delete the file", credPath)
	log.Print("next: systemctl restart easy-waf-api easy-waf-acmed")
	log.Print("hint: first API start recreates GUI user admin / password admin — change password in the UI")
	log.Print("hint: bootstrap did not change EASY_WAF_LISTEN_* — if GUI unreachable from LAN, set EASY_WAF_LISTEN_HTTP=0.0.0.0:8000 and EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443 in easy-waf.env, then restart easy-waf-api")
}

func resetControlPanelAccess() {
	fs := flag.NewFlagSet("reset-control-panel-access", flag.ExitOnError)
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	_ = fs.Parse(os.Args[2:])

	st, err := openStoreFromEnvFile(*envFile, "")
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
	log.Print("note: management binds to loopback only — GUI from another host needs SSH tunnel, or set EASY_WAF_LISTEN_HTTP/HTTPS to 0.0.0.0:8000 / 0.0.0.0:8443 (LAN) then restart easy-waf-api; align nftables (EASY_WAF_NFT_MGMT_LAN)")
	log.Print("optional: review nftables ruleset at /etc/nftables/easy-waf.nft if management ports are too open")
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
	maybeChownStateDirToServiceUser(stateDir)
}

// maybeChownStateDirToServiceUser ensures easy-waf-api (User=easy-waf) can write secrets/ and certs/
// after a root-run wipe recreated directories as root:root.
func maybeChownStateDirToServiceUser(stateDir string) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		return
	}
	cmd := exec.Command("chown", "-R", "easy-waf:easy-waf", stateDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("warning: chown %s to easy-waf:easy-waf: %v: %s", stateDir, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("chowned %s to easy-waf:easy-waf (API/ACME can write state)", stateDir)
}

func logPostWipeHints() {
	log.Print("next: ensure DATABASE_URL in /etc/easy-waf/easy-waf.env matches PostgreSQL user password (see scripts/lib/db-password.sh if install rotated it)")
	log.Print("next: systemctl restart easy-waf-api easy-waf-acmed")
	log.Print("hint: first API start recreates default operator admin/admin — change password in the UI")
}

func resetAppliance() {
	fs := flag.NewFlagSet("reset-appliance", flag.ExitOnError)
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env (for bootstrap and DATABASE_URL lookup)")
	databaseURL := fs.String("database-url", "", "optional: postgres URL for this command only (overrides DATABASE_URL)")
	bootstrap := fs.Bool("bootstrap-credentials", false, "rotate postgres role password + EASY_WAF_ADMIN_TOKEN, update env file, then wipe (requires root)")
	credOut := fs.String("credentials-out", admin.DefaultBootstrapReportPath, "path for generated secrets report (0600)")
	confirm := fs.String("confirm", "", fmt.Sprintf("must be %q to erase all appliance configuration", resetConfirmToken))
	_ = fs.Parse(os.Args[2:])

	if *confirm != resetConfirmToken {
		log.Fatalf("refusing: pass -confirm %s to erase all appliance configuration (DB + state under %s)", resetConfirmToken, *stateDir)
	}

	ctx := context.Background()
	if *bootstrap {
		if err := performBootstrapAndWipe(ctx, *envFile, *stateDir, *credOut, *databaseURL); err != nil {
			log.Fatal(err)
		}
		logPostBootstrapHints(*credOut)
		return
	}

	st, err := openStoreFrom(*databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	wipeApplianceData(ctx, st, *stateDir)
	logPostWipeHints()
}

func factoryReset() {
	fs := flag.NewFlagSet("factory-reset", flag.ExitOnError)
	sure := fs.Bool("i-am-sure", false, "required to proceed (prefer: reset-appliance -confirm RESET)")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env (for bootstrap and DATABASE_URL lookup)")
	databaseURL := fs.String("database-url", "", "optional: postgres URL for this command only (overrides DATABASE_URL)")
	bootstrap := fs.Bool("bootstrap-credentials", false, "rotate postgres role password + EASY_WAF_ADMIN_TOKEN, update env file, then wipe (requires root)")
	credOut := fs.String("credentials-out", admin.DefaultBootstrapReportPath, "path for generated secrets report (0600)")
	_ = fs.Parse(os.Args[2:])

	if !*sure {
		log.Fatal("refusing: pass -i-am-sure to confirm full data wipe (or use: reset-appliance -confirm RESET)")
	}

	ctx := context.Background()
	if *bootstrap {
		if err := performBootstrapAndWipe(ctx, *envFile, *stateDir, *credOut, *databaseURL); err != nil {
			log.Fatal(err)
		}
		logPostBootstrapHints(*credOut)
		return
	}

	st, err := openStoreFrom(*databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	wipeApplianceData(ctx, st, *stateDir)
	logPostWipeHints()
}
