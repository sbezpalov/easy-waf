package bootstrap

import (
	"context"
	"crypto/tls"
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

// RunAPI starts the management API and embedded UI (architecture C: control-plane service).
// Listeners: plain HTTP (default :8000) and TLS HTTPS (default :8443, self-signed bootstrap cert under stateDir/secrets/).
func RunAPI() {
	listenHTTP := flag.String("listen-http", "", "plain HTTP listen (env EASY_WAF_LISTEN_HTTP; default 0.0.0.0:8000)")
	listenHTTPS := flag.String("listen-https", "", "HTTPS listen (env EASY_WAF_LISTEN_HTTPS; default 0.0.0.0:8443)")
	legacyListen := flag.String("listen", "", "deprecated: HTTP listen if -listen-http and EASY_WAF_LISTEN_HTTP are empty")
	stateDirFlag := flag.String("state-dir", "", "State directory (env EASY_WAF_STATE_DIR; default /var/lib/easy-waf)")
	flag.Parse()

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
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_URL")); v != "" {
		eng.Settings.CrowdSecLAPIURL = v
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_KEY")); v != "" {
		eng.Settings.CrowdSecLAPIKey = v
	}
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

	srv := &api.Server{Eng: eng, JWTSecret: jwtSecret, HAProxyMetrics: metrics.NewHAProxyCollector()}
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
	}
	go func() {
		log.Printf("easy-waf-api management HTTP on %s state=%s db=postgresql", httpAddr, stateDir)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

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
	ctx2, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx2)
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(ctx2)
	}
}
