package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
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
	"github.com/easy-waf/easy-waf/internal/geoip"
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

// mergeEnvIntoSettings applies /etc/easy-waf/easy-waf.env CrowdSec (and defaults) into in-memory settings.
func mergeEnvIntoSettings(eng *engine.Engine) {
	if strings.TrimSpace(eng.Settings.CrowdSecLAPIURL) == "" {
		eng.Settings.CrowdSecLAPIURL = defaultCrowdSecLAPIURL
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_URL")); v != "" {
		eng.Settings.CrowdSecLAPIURL = v
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_KEY")); v != "" {
		eng.Settings.CrowdSecLAPIKey = v
	}
}

// RunSyncSettingsOnly loads settings from PostgreSQL, merges env, saves — used by install.sh before first API start.
func RunSyncSettingsOnly() {
	stateDir := strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_STATE_DIR"), "\r", ""))
	if stateDir == "" {
		stateDir = "/var/lib/easy-waf"
	}
	dsn := strings.TrimSpace(strings.ReplaceAll(os.Getenv("DATABASE_URL"), "\r", ""))
	if dsn == "" {
		log.Fatal("DATABASE_URL is required for -sync-settings-only")
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		log.Fatal(err)
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	eng := &engine.Engine{StateDir: stateDir, Store: st}
	ctx := context.Background()
	if err := eng.LoadSettings(ctx); err != nil {
		eng.Settings = config.DefaultSettings(stateDir)
	}
	mergeEnvIntoSettings(eng)
	if err := eng.SaveSettings(ctx); err != nil {
		log.Fatal(err)
	}
}

// RunAPI starts the management API and embedded UI (architecture C: control-plane service).
// Listeners: plain HTTP (default :8000) and TLS HTTPS (default :8443, self-signed bootstrap cert under stateDir/secrets/).
func RunAPI() {
	syncOnly := flag.Bool("sync-settings-only", false, "merge /etc/easy-waf/easy-waf.env into PostgreSQL settings and exit (install.sh)")
	listenHTTP := flag.String("listen-http", "", "plain HTTP listen (env EASY_WAF_LISTEN_HTTP; default 0.0.0.0:8000)")
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

	st, err := store.OpenPostgres(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	eng := &engine.Engine{StateDir: stateDir, Store: st}
	ctx := context.Background()
	if err := eng.LoadSettings(ctx); err != nil {
		log.Printf("settings: using defaults: %v", err)
		eng.Settings = config.DefaultSettings(stateDir)
	}
	mergeEnvIntoSettings(eng)
	if err := eng.SaveSettings(ctx); err != nil {
		log.Printf("persist settings: %v", err)
	}
	eng.GeoIP = geoip.NewRuntime(time.Duration(eng.Settings.GeoIPCacheTTL))

	jwtSecret, err := auth.LoadJWTSecret(stateDir)
	if err != nil {
		log.Fatal(err)
	}
	created, err := st.EnsureDefaultAdmin(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Print("created default operator user admin/admin — must change password on first login")
	}

	httpAddr := strings.TrimSpace(*listenHTTP)
	if httpAddr == "" {
		httpAddr = strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_LISTEN_HTTP"), "\r", ""))
	}
	if httpAddr == "" {
		httpAddr = strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_LISTEN"), "\r", ""))
	}
	if httpAddr == "" && strings.TrimSpace(*legacyListen) != "" {
		httpAddr = strings.TrimSpace(*legacyListen)
	}
	if httpAddr == "" {
		httpAddr = "0.0.0.0:8000"
	}
	rejectUnexpandedSystemdArg("HTTP listen (-listen-http or EASY_WAF_LISTEN_HTTP)", httpAddr)

	httpsDisabled := strings.TrimSpace(os.Getenv("EASY_WAF_MANAGEMENT_HTTPS")) == "0"
	httpsAddr := strings.TrimSpace(*listenHTTPS)
	if httpsAddr == "" {
		httpsAddr = strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_LISTEN_HTTPS"), "\r", ""))
	}
	if httpsAddr == "" {
		httpsAddr = "0.0.0.0:8443"
	}
	if !httpsDisabled {
		rejectUnexpandedSystemdArg("HTTPS listen (-listen-https or EASY_WAF_LISTEN_HTTPS)", httpsAddr)
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
		log.Fatal(err)
	}
	r.Handle("/*", http.FileServer(http.FS(sub)))

	if !httpsDisabled {
		certPath, keyPath, err := mgmttls.EnsureSelfSigned(stateDir)
		if err != nil {
			log.Fatal(err)
		}
		tlsMgr := &mgmttls.Manager{}
		if err := tlsMgr.LoadFromFiles(certPath, keyPath); err != nil {
			log.Fatal(err)
		}
		srv.MgmtTLS = tlsMgr
		srv.MgmtTLSCertPath = certPath
		srv.MgmtTLSKeyPath = keyPath
		log.Printf("management TLS material: %s + %s (replace via UI: Management TLS or PUT /api/v1/settings/management-tls)", certPath, keyPath)
	}

	if os.Getenv("EASY_WAF_ADMIN_TOKEN") != "" {
		log.Print("EASY_WAF_ADMIN_TOKEN is set — legacy API token auth enabled for automation")
	}

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		log.Printf("easy-waf-api management HTTP on %s state=%s db=postgresql", httpAddr, stateDir)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	var acmeInternalSrv *http.Server
	if acAddr := acmeInternalListenAddr(); acAddr != "" {
		wr, err := acmeWebrootPath(stateDir, eng.Settings.ACMEWebrootPath)
		if err != nil {
			log.Fatalf("ACME webroot: %v", err)
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
	if !httpsDisabled {
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
	_ = httpSrv.Shutdown(ctx2)
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(ctx2)
	}
	if acmeInternalSrv != nil {
		_ = acmeInternalSrv.Shutdown(ctx2)
	}
}

func prometheusRefreshLoop(ctx context.Context, srv *api.Server, stateDir string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	refresh := func() {
		if srv.Prom == nil || !srv.Eng.Settings.PrometheusEnabled {
			return
		}
		bg := context.Background()
		sock := metrics.StatsSocketPath(srv.Eng.Settings, stateDir)
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
		cs := crowdsec.Client{BaseURL: srv.Eng.Settings.CrowdSecLAPIURL, APIKey: srv.Eng.Settings.CrowdSecLAPIKey}
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
