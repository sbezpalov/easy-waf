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
	// issueTimeout bounds one issuance: the ACME order, then the apply-lock
	// wait and certificate writes (the HAProxy apply that follows has its own
	// applyTimeout). Lego's own timeouts normally end an issuance long
	// before; whether every Lego step honors the context is not guaranteed,
	// which is why the deadline also covers the writes.
	issueTimeout = 45 * time.Minute
	// claimMargin: every row of a batch is claimed at once and issued one
	// after another, so each issuance must also end this long before the
	// batch's claim turns staleIssuing old; otherwise another worker could
	// reclaim a row still waiting its turn and order it a second time.
	claimMargin = 5 * time.Minute
	// minIssueBudget: an issuance is not started with less time than this
	// left before the claim goes stale. It would only time out (DNS-01
	// propagation alone can take minutes) and be charged an attempt and a
	// backoff for a deadline the worker imposed; the row waits for the next
	// round instead.
	minIssueBudget = 15 * time.Minute
	// applyTimeout bounds the HAProxy apply after a successful issuance. The
	// certificate is stored by then, so it is not tied to the claim deadline;
	// a stop signal cancels it (Apply rolls back cleanly) instead of letting
	// systemd kill the process mid-apply.
	applyTimeout = 5 * time.Minute
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
	// issuance already running keeps going under its own deadline
	// (issueTimeout) until systemd's stop timeout kills the process; a row
	// cut off that way is reclaimed after staleIssuing. A second signal
	// terminates at once.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // restore default handling for a second signal
	}()
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
	claimExpires := now.Add(staleIssuing - claimMargin)
	for i := range due {
		if ctx.Err() != nil {
			// Shutting down: leave the rest claimed; they are picked up again
			// once staleIssuing has passed.
			return
		}
		deadline := time.Now().Add(issueTimeout)
		if claimExpires.Before(deadline) {
			deadline = claimExpires
		}
		if time.Until(deadline) < minIssueBudget {
			// Too little time before the claim goes stale: leave the rest to
			// be reclaimed rather than start an issuance bound to fail.
			log.Printf("acmed: %d claimed certificate(s) left for the next round", len(due)-i)
			return
		}
		ictx, icancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
		issueOne(ictx, ctx, eng, st, &due[i])
		icancel()
	}
}

// issueOne issues c under ctx. stop is the process lifecycle context: it
// cancels the HAProxy apply that follows a successful issuance.
func issueOne(ctx, stop context.Context, eng *engine.Engine, st *store.Store, c *config.Certificate) {
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
		// The failure may be the issuance deadline itself: record it on a
		// fresh short deadline, or the row would stay 'issuing' until
		// staleIssuing instead of getting its retry time.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
		defer cancel()
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
	actx, acancel := context.WithTimeout(stop, applyTimeout)
	defer acancel()
	if err := eng.Apply(actx, "acme"); err != nil {
		log.Printf("apply after acme (the stored certificate goes live with the next apply): %v", err)
	}
}
