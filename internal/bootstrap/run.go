// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/easy-waf/easy-waf/internal/api"
	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/envflag"
	"github.com/easy-waf/easy-waf/internal/metrics"
	"github.com/easy-waf/easy-waf/internal/mgmttls"
	"github.com/easy-waf/easy-waf/internal/store"
	"github.com/easy-waf/easy-waf/internal/webui"
)

// rejectUnexpandedSystemdArg catches ExecStart lines where ${VAR:-default} was passed literally to the binary.
func rejectUnexpandedSystemdArg(label, value string) {
	if strings.Contains(value, "${") {
		log.Fatalf("easy-waf-api: %s is %q: unexpanded ${...} from systemd; use ExecStart=/usr/sbin/easy-waf-api only and set options in /etc/easy-waf/easy-waf.env (packaging/systemd/easy-waf-api.service)", label, value)
	}
}

const defaultCrowdSecLAPIURL = "http://127.0.0.1:8080/"

// mergeEnvIntoSettings applies /etc/easy-waf/easy-waf.env CrowdSec (and defaults) onto settings.
func mergeEnvIntoSettings(gs *config.GlobalSettings) {
	if strings.TrimSpace(gs.CrowdSecLAPIURL) == "" {
		gs.CrowdSecLAPIURL = defaultCrowdSecLAPIURL
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_URL")); v != "" {
		if _, err := crowdsec.ValidateLAPIURL(v, nil); err != nil {
			log.Printf("CROWDSEC_LAPI_URL rejected by destination policy: %v (keeping previous/default local LAPI)", err)
		} else {
			gs.CrowdSecLAPIURL = v
		}
	}
	if _, err := crowdsec.ValidateLAPIURL(gs.CrowdSecLAPIURL, nil); err != nil {
		log.Printf("crowdsec_lapi_url rejected by destination policy: %v; falling back to %s", err, defaultCrowdSecLAPIURL)
		gs.CrowdSecLAPIURL = defaultCrowdSecLAPIURL
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_KEY")); v != "" {
		gs.CrowdSecLAPIKey = v
	}
}

// syncEnvIntoStoredSettings merges the env file into the stored settings. A
// failure to read them is returned rather than replaced by defaults: saving
// defaults over a database that merely hiccupped would wipe the operator's
// configuration.
func syncEnvIntoStoredSettings(ctx context.Context, eng *engine.Engine) error {
	_, err := eng.UpdateSettings(ctx, func(gs config.GlobalSettings) (config.GlobalSettings, error) {
		mergeEnvIntoSettings(&gs)
		return gs, nil
	})
	return err
}

// RunSyncSettingsOnly loads settings from PostgreSQL, merges env, saves — used by install.sh before first API start.
func RunSyncSettingsOnly() {
	if err := runSyncSettingsOnly(); err != nil {
		log.Fatal(err)
	}
}

func runSyncSettingsOnly() error {
	stateDir := strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_STATE_DIR"), "\r", ""))
	if stateDir == "" {
		stateDir = "/var/lib/easy-waf"
	}
	dsn := strings.TrimSpace(strings.ReplaceAll(os.Getenv("DATABASE_URL"), "\r", ""))
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required for -sync-settings-only")
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	eng := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	return syncEnvIntoStoredSettings(context.Background(), eng)
}

// RunAPI starts the management API and embedded UI (architecture C: control-plane service).
// Listeners: plain HTTP (default :8000) and TLS HTTPS (default :8443, self-signed bootstrap cert under stateDir/secrets/).
func RunAPI() {
	syncOnly := flag.Bool("sync-settings-only", false, "merge /etc/easy-waf/easy-waf.env into PostgreSQL settings and exit (install.sh)")
	listenHTTP := flag.String("listen-http", "", "plain HTTP listen (env EASY_WAF_LISTEN_HTTP; default off; loopback or EASY_WAF_ALLOW_INSECURE_HTTP=1 for non-loopback)")
	listenHTTPS := flag.String("listen-https", "", "HTTPS listen (env EASY_WAF_LISTEN_HTTPS; default 0.0.0.0:8443)")
	legacyListen := flag.String("listen", "", "deprecated: HTTP listen if -listen-http and EASY_WAF_LISTEN_HTTP are empty")
	stateDirFlag := flag.String("state-dir", "", "State directory (env EASY_WAF_STATE_DIR; default /var/lib/easy-waf)")
	flag.Parse()

	if *syncOnly {
		RunSyncSettingsOnly()
		return
	}

	stateDir := strings.TrimSpace(*stateDirFlag)
	if stateDir == "" {
		stateDir = strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_STATE_DIR"), "\r", ""))
	}
	if stateDir == "" {
		stateDir = "/var/lib/easy-waf"
	}
	rejectUnexpandedSystemdArg("state directory (-state-dir or EASY_WAF_STATE_DIR)", stateDir)

	dsn := strings.TrimSpace(strings.ReplaceAll(os.Getenv("DATABASE_URL"), "\r", ""))
	if dsn == "" {
		log.Fatal("DATABASE_URL is required (PostgreSQL connection string); check /etc/easy-waf/easy-waf.env and unit EnvironmentFile=")
	}

	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		log.Fatal(err)
	}

	if err := runAPIService(dsn, stateDir, listenHTTP, listenHTTPS, legacyListen); err != nil {
		log.Fatal(err)
	}
}

func runAPIService(dsn, stateDir string, listenHTTP, listenHTTPS, legacyListen *string) error {
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	eng := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	ctx := context.Background()
	if err := syncEnvIntoStoredSettings(ctx, eng); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	go reconcileEdgeAtStartup(eng)

	jwtSecret, err := auth.LoadJWTSecret(stateDir)
	if err != nil {
		return err
	}
	created, enrollPath, err := st.EnsureOperatorEnrollment(ctx, stateDir)
	if err != nil {
		return err
	}
	if created {
		log.Printf("operator enrollment required; one-time secret written to %s (mode 0600). Print locally with: easy-waf-admin print-enrollment. Do not copy the secret into logs.", enrollPath)
	} else if enrollPath != "" {
		pending, _ := st.EnrollmentPending(ctx)
		if pending {
			log.Printf("operator enrollment still pending; secret file %s (not logged). Print locally with: easy-waf-admin print-enrollment", enrollPath)
		}
	}

	httpDec := ResolveManagementHTTP(*listenHTTP, *legacyListen)
	if httpDec.Refused {
		log.Print(httpDec.Warning)
	}
	httpAddr := httpDec.Addr
	if httpAddr != "" {
		rejectUnexpandedSystemdArg("HTTP listen (-listen-http or EASY_WAF_LISTEN_HTTP)", httpAddr)
	}
	if httpDec.Warning != "" && httpDec.Insecure {
		log.Print(httpDec.Warning)
	}

	httpsDisabled := strings.TrimSpace(os.Getenv("EASY_WAF_MANAGEMENT_HTTPS")) == "0"
	httpsAddr := ResolveManagementHTTPS(*listenHTTPS, httpsDisabled)
	if httpsAddr != "" {
		rejectUnexpandedSystemdArg("HTTPS listen (-listen-https or EASY_WAF_LISTEN_HTTPS)", httpsAddr)
	}
	if httpAddr == "" && httpsAddr == "" {
		return fmt.Errorf("no management listener: enable HTTPS (default :8443) or set EASY_WAF_LISTEN_HTTP=127.0.0.1:8000")
	}

	prom := metrics.NewPrometheusExporter()
	srv := &api.Server{
		Eng:            eng,
		JWTSecret:      jwtSecret,
		HAProxyMetrics: metrics.NewHAProxyCollector(),
		Prom:           prom,
		LoginRL:        api.NewLoginRateLimiter(5*time.Minute, 10, 15*time.Minute),
	}
	ctxRefresh, stopPromRefresh := context.WithCancel(context.Background())
	defer stopPromRefresh()
	go prometheusRefreshLoop(ctxRefresh, srv, stateDir)

	r := srv.Router()

	sub, err := fs.Sub(webui.Assets, "dist")
	if err != nil {
		return err
	}
	r.Handle("/*", http.FileServer(http.FS(sub)))

	if httpsAddr != "" {
		certPath, keyPath, err := mgmttls.EnsureSelfSigned(stateDir)
		if err != nil {
			return err
		}
		tlsMgr := &mgmttls.Manager{}
		if err := tlsMgr.LoadFromFiles(certPath, keyPath); err != nil {
			return err
		}
		srv.MgmtTLS = tlsMgr
		srv.MgmtTLSCertPath = certPath
		srv.MgmtTLSKeyPath = keyPath
		log.Printf("management TLS material: %s + %s (replace via UI: Management TLS or PUT /api/v1/settings/management-tls)", certPath, keyPath)
	}

	if os.Getenv("EASY_WAF_ADMIN_TOKEN") != "" {
		log.Print("EASY_WAF_ADMIN_TOKEN is set — legacy API token auth enabled for automation")
	}

	var httpSrv *http.Server
	if httpAddr != "" {
		httpSrv = &http.Server{
			Addr:              httpAddr,
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if httpDec.Loopback {
				log.Printf("easy-waf-api management HTTP (loopback) on %s state=%s db=postgresql", httpAddr, stateDir)
			} else {
				log.Printf("easy-waf-api management HTTP (INSECURE legacy) on %s state=%s db=postgresql", httpAddr, stateDir)
			}
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	} else {
		log.Printf("easy-waf-api management HTTP disabled (default); use HTTPS or set EASY_WAF_LISTEN_HTTP=127.0.0.1:8000. /health is on the HTTPS listener. ACME HTTP-01 stays on EASY_WAF_ACME_INTERNAL_HTTP.")
	}

	var acmeInternalSrv *http.Server
	acAddr, acBackend := acmeInternalAddrs(eng.Settings().ACMEInternalHTTP)
	if acAddr != "" && acAddr != acBackend {
		log.Printf("WARNING: EASY_WAF_ACME_INTERNAL_HTTP=%s moves the HTTP-01 helper, but the generated HAProxy backend dials %s (setting acme_internal_http) — HTTP-01 will fail. Change the setting instead, or unset the variable.", acAddr, acBackend)
	}
	if acAddr != "" {
		wr, err := acmeWebrootPath(stateDir, eng.Settings().ACMEWebrootPath)
		if err != nil {
			return fmt.Errorf("ACME webroot: %w", err)
		}
		acmeInternalSrv = &http.Server{
			Addr:              acAddr,
			Handler:           acmeChallengeHandler(wr),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func(srv *http.Server) {
			log.Printf("easy-waf-api ACME HTTP-01 loopback on %s (webroot %s)", acAddr, wr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("ACME HTTP-01 loopback: %v", err)
			}
		}(acmeInternalSrv)
	}

	var httpsSrv *http.Server
	if httpsAddr != "" {
		tlsConf := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: srv.MgmtTLS.GetCertificate,
		}
		httpsSrv = &http.Server{
			Addr:              httpsAddr,
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig:         tlsConf,
		}
		go func() {
			log.Printf("easy-waf-api management HTTPS on %s (browser will warn until you install a trusted cert)", httpsAddr)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	stopPromRefresh()
	ctx2, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if httpSrv != nil {
		_ = httpSrv.Shutdown(ctx2)
	}
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(ctx2)
	}
	if acmeInternalSrv != nil {
		_ = acmeInternalSrv.Shutdown(ctx2)
	}
	return nil
}

func prometheusRefreshLoop(ctx context.Context, srv *api.Server, stateDir string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	refresh := func() {
		if srv.Prom == nil || !srv.Eng.Settings().PrometheusEnabled {
			return
		}
		bg := context.Background()
		sock := metrics.StatsSocketPath(srv.Eng.Settings(), stateDir)
		if rep, _ := srv.HAProxyMetrics.Fetch(sock); rep != nil {
			srv.Prom.UpdateFromHAProxyReport(rep)
		}
		if certs, err := srv.Eng.Store.ListCertificates(bg); err == nil {
			summary := api.BuildCertificateSummaryResponse(certs, time.Now().UTC())
			srv.Prom.UpdateFromCertSummary(summary)
		}
		if apps, err := srv.Eng.Store.ListApplications(bg); err == nil {
			srv.Prom.UpdateFromAppStats(apps)
		}
		cs := crowdsec.Client{BaseURL: srv.Eng.Settings().CrowdSecLAPIURL, APIKey: srv.Eng.Settings().CrowdSecLAPIKey}
		raw, err := cs.DecisionsSample(bg)
		n := 0
		if err == nil {
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) == nil {
				n = len(arr)
			}
		}
		srv.Prom.SetCrowdSecDecisionSampleSize(n)
		localRows, err1 := srv.Eng.Store.ListIPBLLocal(bg)
		extSrc, err2 := srv.Eng.Store.ListIPBLExternalSources(bg)
		if err1 == nil && err2 == nil {
			srv.Prom.SetIPBLEntries(countEnabledIPBLLocal(localRows), countEnabledIPBLFeeds(extSrc))
		}
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func countEnabledIPBLLocal(rows []config.IPBLLocalEntry) int {
	n := 0
	for _, e := range rows {
		if !e.Enabled {
			continue
		}
		if strings.TrimSpace(e.CIDR) == "" {
			continue
		}
		n++
	}
	return n
}

func countEnabledIPBLFeeds(srcs []config.IPBLExternalSource) int {
	n := 0
	for _, s := range srcs {
		if s.Enabled {
			n++
		}
	}
	return n
}

// reconcileEdgeAtStartup brings the edge in line with the database once the
// API is up: after an upgrade that changed the template, or a restore, the new
// config otherwise waited for the next manual Apply. It applies only when the
// rendered set differs from the live one, and never blocks startup.
func reconcileEdgeAtStartup(eng *engine.Engine) {
	if envflag.Enabled("EASY_WAF_NO_AUTO_APPLY") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	applied, err := eng.ApplyIfChanged(ctx, "startup-reconcile")
	switch {
	case err != nil:
		log.Printf("startup reconcile: edge not updated: %v", err)
	case applied:
		log.Printf("startup reconcile: edge config differed from the database; applied")
	}
}
