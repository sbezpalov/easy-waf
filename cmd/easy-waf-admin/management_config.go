package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/easy-waf/easy-waf/internal/admin"
	"github.com/easy-waf/easy-waf/internal/api"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

// openStoreFromEnvFile resolves DATABASE_URL from -database-url, then env file, then the environment.
func openStoreFromEnvFile(envFile, databaseURL string) (*store.Store, error) {
	dsn, err := resolveDSNForWipe(envFile, databaseURL)
	if err != nil {
		return nil, err
	}
	return store.OpenPostgres(dsn)
}

func managementConfig() {
	if err := runManagementConfig(); err != nil {
		log.Fatal(err)
	}
}

func runManagementConfig() error {
	fs := flag.NewFlagSet("management-config", flag.ExitOnError)
	envFile := fs.String("env-file", "/etc/easy-waf/easy-waf.env", "path to easy-waf.env (DATABASE_URL + listen variables)")
	stateDir := fs.String("state-dir", "/var/lib/easy-waf", "state directory")
	databaseURL := fs.String("database-url", "", "optional: postgres DSN (overrides DATABASE_URL from env file / environment)")
	listenHTTP := fs.String("listen-http", "", "write EASY_WAF_LISTEN_HTTP (e.g. 0.0.0.0:8000); empty = unchanged unless -listen-loopback/-listen-lan")
	listenHTTPS := fs.String("listen-https", "", "write EASY_WAF_LISTEN_HTTPS (e.g. 0.0.0.0:8443)")
	listenLoopback := fs.Bool("listen-loopback", false, "set listen to 127.0.0.1:8000 and 127.0.0.1:8443")
	listenLAN := fs.Bool("listen-lan", false, "set listen to 0.0.0.0:8000 and 0.0.0.0:8443 (LAN GUI; restart easy-waf-api)")
	managementCIDRs := fs.String("management-cidrs", "", "comma-separated CIDRs for GUI/API ACL (replaces list in database)")
	defaultCIDRs := fs.Bool("default-management-cidrs", false, "reset management_allowed_cidrs to RFC1918 + loopback defaults")
	_ = fs.Parse(os.Args[2:])

	if *listenLoopback && *listenLAN {
		return fmt.Errorf("refusing: use only one of -listen-loopback or -listen-lan")
	}
	if *listenLoopback && (strings.TrimSpace(*listenHTTP) != "" || strings.TrimSpace(*listenHTTPS) != "") {
		return fmt.Errorf("refusing: do not combine -listen-loopback with -listen-http/-listen-https")
	}
	if *listenLAN && (strings.TrimSpace(*listenHTTP) != "" || strings.TrimSpace(*listenHTTPS) != "") {
		return fmt.Errorf("refusing: do not combine -listen-lan with -listen-http/-listen-https")
	}
	if *defaultCIDRs && strings.TrimSpace(*managementCIDRs) != "" {
		return fmt.Errorf("refusing: use either -default-management-cidrs or -management-cidrs, not both")
	}

	st, err := openStoreFromEnvFile(*envFile, *databaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	eng := &engine.Engine{StateDir: *stateDir, Store: st}
	if err := eng.LoadSettings(ctx); err != nil {
		_ = st.Close()
		return fmt.Errorf("load settings: %w", err)
	}

	envChanged := false
	dbChanged := false

	switch {
	case *listenLoopback:
		if err := applyListenEnv(*envFile, "127.0.0.1:8000", "127.0.0.1:8443"); err != nil {
			return err
		}
		envChanged = true
	case *listenLAN:
		if err := applyListenEnv(*envFile, "0.0.0.0:8000", "0.0.0.0:8443"); err != nil {
			return err
		}
		envChanged = true
	default:
		if s := strings.TrimSpace(*listenHTTP); s != "" {
			if err := admin.UpsertEnvKey(*envFile, "EASY_WAF_LISTEN_HTTP", s); err != nil {
				return fmt.Errorf("update env file: %w", err)
			}
			_ = admin.RemoveEnvKey(*envFile, "EASY_WAF_LISTEN")
			envChanged = true
		}
		if s := strings.TrimSpace(*listenHTTPS); s != "" {
			if err := admin.UpsertEnvKey(*envFile, "EASY_WAF_LISTEN_HTTPS", s); err != nil {
				return fmt.Errorf("update env file: %w", err)
			}
			_ = admin.RemoveEnvKey(*envFile, "EASY_WAF_LISTEN")
			envChanged = true
		}
	}

	if *defaultCIDRs {
		eng.Settings.ManagementAllowedCIDRs = append([]string(nil), config.DefaultManagementCIDRs()...)
		if err := eng.SaveSettings(ctx); err != nil {
			return fmt.Errorf("save settings: %w", err)
		}
		dbChanged = true
	} else if strings.TrimSpace(*managementCIDRs) != "" {
		list, err := splitCommaCIDRs(*managementCIDRs)
		if err != nil {
			return err
		}
		if err := api.ValidateManagementCIDRs(list); err != nil {
			return fmt.Errorf("management CIDRs: %w", err)
		}
		eng.Settings.ManagementAllowedCIDRs = list
		if err := eng.SaveSettings(ctx); err != nil {
			return fmt.Errorf("save settings: %w", err)
		}
		dbChanged = true
	}

	if dbChanged {
		if err := eng.LoadSettings(ctx); err != nil {
			return fmt.Errorf("reload settings: %w", err)
		}
	}

	printManagementConfiguration(os.Stdout, *envFile, eng)

	if envChanged || dbChanged {
		fmt.Fprintln(os.Stderr)
		log.Print("updated — restart easy-waf-api to apply: sudo systemctl restart easy-waf-api.service")
	}
	return nil
}

func applyListenEnv(envFile, httpAddr, httpsAddr string) error {
	if err := admin.UpsertEnvKey(envFile, "EASY_WAF_LISTEN_HTTP", httpAddr); err != nil {
		return err
	}
	if err := admin.UpsertEnvKey(envFile, "EASY_WAF_LISTEN_HTTPS", httpsAddr); err != nil {
		return err
	}
	_ = admin.RemoveEnvKey(envFile, "EASY_WAF_LISTEN")
	return nil
}

func splitCommaCIDRs(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CIDRs after parsing -management-cidrs (use comma-separated prefixes, e.g. 10.0.0.0/8,192.168.0.0/16)")
	}
	return out, nil
}

func printManagementConfiguration(out io.Writer, envFile string, eng *engine.Engine) {
	fmt.Fprintf(out, "# Easy WAF — management configuration\n\n")
	fmt.Fprintf(out, "## Env file: %s\n", envFile)

	httpListen, httpsListen, stateDir, legacyListen := readListenFromEnvFile(envFile)
	fmt.Fprintf(out, "EASY_WAF_LISTEN_HTTP=%s\n", httpListen)
	fmt.Fprintf(out, "EASY_WAF_LISTEN_HTTPS=%s\n", httpsListen)
	if stateDir != "" {
		fmt.Fprintf(out, "EASY_WAF_STATE_DIR=%s\n", stateDir)
	}
	if legacyListen != "" {
		fmt.Fprintf(out, "# deprecated EASY_WAF_LISTEN=%s (prefer LISTEN_HTTP / LISTEN_HTTPS)\n", legacyListen)
	}

	if strings.HasPrefix(httpListen, "127.") || strings.HasPrefix(httpsListen, "127.") {
		fmt.Fprintln(out, "\n# Note: loopback HTTP/HTTPS — open GUI via SSH port-forward or switch to -listen-lan.")
	}

	fmt.Fprintln(out, "\n## Database: management_allowed_cidrs (GUI + API except /health)")
	stored := eng.Settings.ManagementAllowedCIDRs
	if len(stored) == 0 {
		fmt.Fprintln(out, "(stored empty — running API uses built-in defaults until next save)")
		defs := config.DefaultManagementCIDRs()
		for _, c := range defs {
			fmt.Fprintf(out, "  %s\n", c)
		}
	} else {
		for _, c := range stored {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}

	fmt.Fprintln(out, "\n## Effective allowlist (what a new API process uses)")
	for _, c := range effectiveManagementCIDRs(stored) {
		fmt.Fprintf(out, "  %s\n", c)
	}

	if os.Getenv("EASY_WAF_BYPASS_MGMT_ACL") == "1" {
		fmt.Fprintln(out, "\n# WARNING: EASY_WAF_BYPASS_MGMT_ACL=1 — application ACL disabled for the API process that inherited this env.")
	}
}

func readListenFromEnvFile(envFile string) (httpListen, httpsListen, stateDir, legacyListen string) {
	httpListen = "(unset — API default 0.0.0.0:8000)"
	httpsListen = "(unset — API default 0.0.0.0:8443)"
	if _, err := os.Stat(envFile); err != nil {
		msg := fmt.Sprintf("(cannot read %s: %v)", envFile, err)
		return msg, msg, "", ""
	}
	if v, err := admin.ReadEnvKey(envFile, "EASY_WAF_LISTEN_HTTP"); err == nil && strings.TrimSpace(v) != "" {
		httpListen = strings.TrimSpace(v)
	}
	if v, err := admin.ReadEnvKey(envFile, "EASY_WAF_LISTEN_HTTPS"); err == nil && strings.TrimSpace(v) != "" {
		httpsListen = strings.TrimSpace(v)
	}
	if v, err := admin.ReadEnvKey(envFile, "EASY_WAF_STATE_DIR"); err == nil && strings.TrimSpace(v) != "" {
		stateDir = strings.TrimSpace(v)
	}
	if v, err := admin.ReadEnvKey(envFile, "EASY_WAF_LISTEN"); err == nil && strings.TrimSpace(v) != "" {
		legacyListen = strings.TrimSpace(v)
	}
	return httpListen, httpsListen, stateDir, legacyListen
}

func effectiveManagementCIDRs(stored []string) []string {
	if len(stored) == 0 {
		return append([]string(nil), config.DefaultManagementCIDRs()...)
	}
	return append([]string(nil), stored...)
}
