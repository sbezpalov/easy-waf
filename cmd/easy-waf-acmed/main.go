// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/easy-waf/easy-waf/internal/acme"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/envflag"
	"github.com/easy-waf/easy-waf/internal/store"
)

const (
	// renewWindow: ready ACME certificates are renewed this long before expiry.
	renewWindow = 30 * 24 * time.Hour
	// staleIssuing: a row still 'issuing' after this long belongs to a worker
	// that died mid-issuance; it is claimed again. Lego's own timeouts, DNS
	// propagation included, finish well inside it.
	staleIssuing = time.Hour
	// issueTimeout bounds one issuance end to end (ACME, apply lock, writes,
	// apply). It stays below staleIssuing so another worker never reclaims a
	// row that is still being worked on. Lego's own timeouts normally end an
	// issuance long before; whether every Lego step honors the context is
	// not guaranteed, which is why the deadline also covers what follows.
	issueTimeout = 45 * time.Minute
	// dbTimeout bounds the per-tick settings load and claim queries.
	dbTimeout = 30 * time.Second
)

// ACME worker (architecture C): issues and renews certificates (HTTP-01 and DNS-01) using shared PostgreSQL state.
func main() {
	dsn := strings.TrimSpace(strings.ReplaceAll(os.Getenv("DATABASE_URL"), "\r", ""))
	if dsn == "" {
		log.Fatal("DATABASE_URL is required; check /etc/easy-waf/easy-waf.env")
	}
	stateDir := strings.TrimSpace(os.Getenv("EASY_WAF_STATE_DIR"))
	if stateDir == "" {
		stateDir = "/var/lib/easy-waf"
	}
	_ = os.MkdirAll(stateDir, 0o750)

	st, err := store.OpenPostgres(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	eng := engine.New(stateDir, st, config.DefaultSettings(stateDir))
	tick := 30 * time.Second
	if v := os.Getenv("EASY_WAF_ACME_TICK"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			tick = d
		}
	}

	log.Printf("easy-waf-acmed started state=%s tick=%s", stateDir, tick)

	// SIGTERM/SIGINT stop the loop: no new claims, no further sleeps. An
	// issuance already running finishes under its own deadline (issueTimeout),
	// so a stop does not strand the row half-written.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	for {
		runOnce(ctx, eng, st)
		select {
		case <-ctx.Done():
			log.Printf("easy-waf-acmed stopping")
			return
		case <-time.After(tick):
		}
	}
}

// runOnce loads settings, claims due certificates and issues them.
func runOnce(ctx context.Context, eng *engine.Engine, st *store.Store) {
	qctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	if err := eng.LoadSettings(qctx); err != nil {
		log.Printf("settings: %v", err)
		return
	}
	if eng.Settings().ACMEEmail == "" {
		log.Printf("acmed: ACMEEmail not set in global settings — idle")
		return
	}

	now := time.Now().UTC()
	due, err := st.ClaimCertificatesACME(qctx, store.ACMEClaimWindow{
		Now:          now,
		RenewBefore:  now.Add(renewWindow),
		StaleIssuing: staleIssuing,
		Limit:        5,
	})
	if err != nil {
		log.Printf("claim certificates: %v", err)
	}
	for i := range due {
		if ctx.Err() != nil {
			// Shutting down: leave the rest claimed; they are picked up again
			// once staleIssuing has passed.
			return
		}
		ictx, icancel := context.WithTimeout(context.WithoutCancel(ctx), issueTimeout)
		issueOne(ictx, eng, st, &due[i])
		icancel()
	}
}

func issueOne(ctx context.Context, eng *engine.Engine, st *store.Store, c *config.Certificate) {
	email := eng.Settings().ACMEEmail
	webroot := eng.Settings().ACMEWebrootPath
	if webroot == "" {
		webroot = filepath.Join(eng.StateDir, "acme", "webroot")
	}
	accountKey := filepath.Join(eng.StateDir, "acme", "account.pem")

	domains := []string{c.PrimaryDomain}
	domains = append(domains, c.SAN...)

	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	if mode == "" {
		mode = "http-01"
	}

	staging := c.Staging || eng.Settings().ACMEStaging

	var res *certificate.Resource
	var err error

	switch mode {
	case "dns-01":
		provider := strings.TrimSpace(c.DNSProvider)
		if provider == "" {
			provider = acme.DefaultDNSProvider
		}
		envFile := strings.TrimSpace(c.DNSCredentialsEnvFile)
		if envFile == "" {
			err = fmt.Errorf("dns-01: dns_credentials_env_file must point to a root-readable env file on the appliance")
			break
		}
		res, err = acme.IssueDNS01(ctx, email, domains, staging, accountKey, provider, envFile, eng.Settings().ACMEDNSResolvers)
	case "http-01":
		res, err = acme.IssueHTTP01Webroot(ctx, email, domains, webroot, staging, accountKey)
	default:
		err = fmt.Errorf("unsupported certificate mode %q (use http-01 or dns-01)", c.Mode)
	}

	if err == nil {
		err = eng.WithApplyLock(ctx, func() error {
			return st.CompleteCertificateACME(ctx, c, func() (store.ACMEResult, error) {
				full, key, nb, na, werr := acme.WriteCertificateResource(eng.StateDir, c.ID, res)
				return store.ACMEResult{FullchainPath: full, KeyPath: key, NotBefore: nb, NotAfter: na, Mode: mode}, werr
			})
		})
	}
	if errors.Is(err, store.ErrACMEClaimLost) {
		log.Printf("acme id=%s: row changed during issuance; result discarded", c.ID)
		return
	}
	if err != nil {
		next := time.Now().Add(acme.RetryBackoff(c.ACMEAttempts + 1))
		if ferr := st.FailCertificateACME(ctx, c, err.Error(), next); ferr != nil && !errors.Is(ferr, store.ErrACMEClaimLost) {
			log.Printf("acme id=%s: record failure: %v", c.ID, ferr)
		}
		_ = st.AppendAudit(ctx, "acme.failed", map[string]string{"id": c.ID, "error": err.Error(), "next_attempt_at": next.UTC().Format(time.RFC3339)})
		log.Printf("acme issue failed id=%s mode=%s attempt=%d next=%s: %v", c.ID, mode, c.ACMEAttempts+1, next.UTC().Format(time.RFC3339), err)
		return
	}
	_ = st.AppendAudit(ctx, "acme.issued", map[string]string{"id": c.ID, "domains": strings.Join(domains, ","), "mode": mode})

	if envflag.Enabled("EASY_WAF_ACME_SKIP_APPLY") {
		return
	}
	if err := eng.Apply(ctx, "acme"); err != nil {
		log.Printf("apply after acme: %v", err)
	}
}
