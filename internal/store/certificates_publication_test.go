// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/acme"
	"github.com/easy-waf/easy-waf/internal/testcert"
	"github.com/go-acme/lego/v4/certificate"
)

func TestACMERequestCannotOverwriteCompletionOrResurrectDeletion(t *testing.T) {
	st := openFresh(t, freshSchemaDSN(t))
	ctx := t.Context()
	c := newACMECert(t, st, "pending", nil)
	stale := certByID(t, st, c.ID)
	now := time.Now().UTC()
	claimed := claimOnly(t, st, ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}, c.ID)
	if claimed == nil {
		t.Fatal("not claimed")
	}
	var result ACMEResult
	if err := st.CompleteCertificateACME(ctx, claimed, func() (ACMEResult, error) { result = publicationWrite(t, t.TempDir(), c.ID); return result, nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.RequestCertificateACME(ctx, &stale); !errors.Is(err, ErrCertificateChanged) {
		t.Fatalf("stale request: %v", err)
	}
	row := certByID(t, st, c.ID)
	if row.ACMEStatus != "ready" || row.FullchainPath != result.FullchainPath || row.PEMKeyPath != result.KeyPath || len(publicationTokens(t, st)) != 1 {
		t.Fatal("stale request damaged completion")
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE certificates SET acme_status='failed', acme_attempts=3, last_error='old failure', acme_next_attempt_at=now()+interval '1 hour' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	fresh := certByID(t, st, c.ID)
	fresh.Mode = "dns-01"
	fresh.DNSProvider = "cloudflare"
	fresh.DNSCredentialsEnvFile = "/fixture/dns.env"
	fresh.PrimaryDomain = "stale-snapshot.example.test"
	fresh.FullchainPath = "must-not-be-written"
	if err := st.RequestCertificateACME(ctx, &fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.ACMEStatus != "pending" || fresh.ACMEAttempts != 0 || fresh.ACMENextAttemptAt != nil || fresh.LastError != "" || fresh.PrimaryDomain != row.PrimaryDomain || fresh.FullchainPath != row.FullchainPath || fresh.PEMKeyPath != row.PEMKeyPath || fresh.Mode != "dns-01" || fresh.DNSProvider != "cloudflare" {
		t.Fatal("request changed unrelated columns or returned stale metadata")
	}
	if err := st.DeleteCertificate(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RequestCertificateACME(ctx, &fresh); !errors.Is(err, ErrCertificateChanged) {
		t.Fatalf("deleted request: %v", err)
	}
	rows, err := st.ListCertificates(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("request resurrected deleted certificate")
	}
}

func publicationResource(t *testing.T) *certificate.Resource {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pem")
	if err := testcert.WriteBundle(path, "publication.example.test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, key := pem.Decode(b)
	if block == nil {
		t.Fatal("fixture certificate unavailable")
	}
	return &certificate.Resource{Certificate: pem.EncodeToMemory(block), PrivateKey: key}
}

func TestACMEPublicationCrashHelper(t *testing.T) {
	mode := os.Getenv("EASY_WAF_PUBLICATION_CRASH_TEST")
	if mode == "" {
		return
	}
	st := testStore(t)
	row := certByID(t, st, "crash-publication")
	state, err := filepath.Abs("state")
	if err != nil {
		t.Fatal(err)
	}
	err = st.CompleteCertificateACME(t.Context(), &row, func() (ACMEResult, error) {
		result := publicationWrite(t, state, row.ID)
		if mode == "before-commit" {
			_, _ = io.WriteString(os.Stdout, "ready\n")
			for {
				time.Sleep(time.Hour)
			}
		}
		return result, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(os.Stdout, "ready\n")
	for {
		time.Sleep(time.Hour)
	}
}

func TestACMEPublicationSurvivesProcessDeath(t *testing.T) {
	for _, mode := range []string{"before-commit", "after-commit"} {
		t.Run(mode, func(t *testing.T) {
			dsn := freshSchemaDSN(t)
			st := openFresh(t, dsn)
			ctx := t.Context()
			c := newACMECert(t, st, "pending", nil)
			// Use a fixed helper identity; no filesystem path is taken from env.
			if err := st.DeleteCertificate(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
			c.ID = "crash-publication"
			old := publicationWrite(t, t.TempDir(), c.ID)
			c.FullchainPath, c.PEMKeyPath = old.FullchainPath, old.KeyPath
			if err := st.UpsertCertificate(ctx, c); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if claimOnly(t, st, ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}, c.ID) == nil {
				t.Fatal("crash fixture not claimed")
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, executable, "-test.run=^TestACMEPublicationCrashHelper$")
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "DATABASE_URL="+dsn, "EASY_WAF_PUBLICATION_CRASH_TEST="+mode)
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				_ = output.Close()
				t.Fatal(err)
			}
			defer func() {
				cancel()
				if cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			if ready, err := bufio.NewReader(output).ReadString('\n'); err != nil || ready != "ready\n" {
				t.Fatal("crash helper did not reach publication boundary")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil || childCtx.Err() != nil {
				t.Fatal("helper was not killed at the requested publication boundary")
			}
			// This lock waits for the dead client's transaction to settle.
			queryCtx, queryCancel := context.WithTimeout(ctx, 5*time.Second)
			defer queryCancel()
			var status string
			if err := st.db.QueryRowContext(queryCtx, `SELECT acme_status FROM certificates WHERE id = $1 FOR UPDATE`, c.ID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			reopened := openFresh(t, dsn)
			row := certByID(t, reopened, c.ID)
			tokens := publicationTokens(t, reopened)
			if mode == "before-commit" {
				if status != "issuing" || row.FullchainPath != old.FullchainPath || row.PEMKeyPath != old.KeyPath || len(tokens) != 0 {
					t.Fatal("process death published an uncommitted generation")
				}
			} else if status != "ready" || row.FullchainPath == old.FullchainPath || len(tokens) != 1 {
				t.Fatal("process death lost the committed generation or apply intent")
			}
			full, err := os.ReadFile(row.FullchainPath)
			if err != nil {
				t.Fatal("surviving row has no certificate")
			}
			key, err := os.ReadFile(row.PEMKeyPath)
			if err != nil {
				t.Fatal("surviving row has no private key")
			}
			if _, err := tls.X509KeyPair(full, key); err != nil {
				t.Fatal("process death left a mismatched certificate pair")
			}
		})
	}
}

func publicationWrite(t *testing.T, state, id string) ACMEResult {
	t.Helper()
	full, key, nb, na, err := acme.WriteCertificateResource(state, id, publicationResource(t))
	if err != nil {
		t.Fatal(err)
	}
	return ACMEResult{FullchainPath: full, KeyPath: key, NotBefore: nb, NotAfter: na, Mode: "http-01"}
}

func publicationTokens(t *testing.T, st *Store) []ACMEApplyToken {
	t.Helper()
	tokens, err := st.PendingCertificateACMEApplies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestACMEPublicationCommitsPairAndTokenTogether(t *testing.T) {
	st := openFresh(t, freshSchemaDSN(t))
	ctx := context.Background()
	c := newACMECert(t, st, "pending", nil)
	state := t.TempDir()
	for attempt := range 2 {
		if attempt > 0 {
			row := certByID(t, st, c.ID)
			row.ACMEStatus = "pending"
			if err := st.UpsertCertificate(ctx, &row); err != nil {
				t.Fatal(err)
			}
		}
		before := certByID(t, st, c.ID)
		oldTokens := publicationTokens(t, st)
		now := time.Now().UTC()
		claimed := claimOnly(t, st, ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}, c.ID)
		if claimed == nil {
			t.Fatal("certificate not claimed")
		}
		var result ACMEResult
		err := st.CompleteCertificateACME(ctx, claimed, func() (ACMEResult, error) {
			result = publicationWrite(t, state, c.ID)
			visible := certByID(t, st, c.ID)
			if visible.ACMEStatus != "issuing" || visible.FullchainPath != before.FullchainPath {
				t.Fatal("uncommitted generation visible in certificate row")
			}
			if got := publicationTokens(t, st); len(got) != len(oldTokens) || len(got) > 0 && got[0] != oldTokens[0] {
				t.Fatal("uncommitted apply token visible")
			}
			return result, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		row := certByID(t, st, c.ID)
		if row.ACMEStatus != "ready" || row.FullchainPath != result.FullchainPath || row.PEMKeyPath != result.KeyPath || row.NotAfter == nil || !row.NotAfter.Equal(result.NotAfter) {
			t.Fatal("ready row does not describe the committed generation")
		}
		full, err := os.ReadFile(row.FullchainPath)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(row.PEMKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tls.X509KeyPair(full, key); err != nil {
			t.Fatal("ready row points at an incomplete pair")
		}
		tokens := publicationTokens(t, st)
		if len(tokens) != 1 || tokens[0].CertificateID != c.ID || tokens[0].Generation == "" {
			t.Fatal("publication has no durable apply token")
		}
		if attempt > 0 {
			if tokens[0] == oldTokens[0] {
				t.Fatal("renewal reused previous apply token")
			}
			if err := st.AcknowledgeCertificateACMEApplies(ctx, oldTokens); err != nil {
				t.Fatal(err)
			}
			if got := publicationTokens(t, st); len(got) != 1 || got[0] != tokens[0] {
				t.Fatal("stale acknowledgement erased a concurrent renewal")
			}
		}
	}
	if err := st.AcknowledgeCertificateACMEApplies(ctx, publicationTokens(t, st)); err != nil {
		t.Fatal(err)
	}
	if len(publicationTokens(t, st)) != 0 {
		t.Fatal("successful acknowledgement left work pending")
	}
}

func TestACMEPublicationRollbackKeepsOldPaths(t *testing.T) {
	st := openFresh(t, freshSchemaDSN(t))
	ctx := context.Background()
	c := newACMECert(t, st, "pending", nil)
	state := t.TempDir()
	old := publicationWrite(t, state, c.ID)
	c.FullchainPath, c.PEMKeyPath = old.FullchainPath, old.KeyPath
	if err := st.UpsertCertificate(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Fail after the ready UPDATE, while inserting its transactional apply token.
	for _, statement := range []string{
		`CREATE FUNCTION reject_acme_apply() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected apply-token failure'; END $$`,
		`CREATE TRIGGER reject_acme_apply BEFORE INSERT OR UPDATE ON acme_apply_pending FOR EACH ROW EXECUTE FUNCTION reject_acme_apply()`,
	} {
		if _, err := st.db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	claimed := claimOnly(t, st, ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}, c.ID)
	if claimed == nil {
		t.Fatal("certificate not claimed")
	}
	var abandoned ACMEResult
	err := st.CompleteCertificateACME(ctx, claimed, func() (ACMEResult, error) {
		abandoned = publicationWrite(t, state, c.ID)
		return abandoned, nil
	})
	if err == nil {
		t.Fatal("injected transaction failure was ignored")
	}
	row := certByID(t, st, c.ID)
	if row.ACMEStatus != "issuing" || row.FullchainPath != old.FullchainPath || row.PEMKeyPath != old.KeyPath || len(publicationTokens(t, st)) != 0 {
		t.Fatal("failed transaction changed published paths or created pending work")
	}
	for _, path := range []string{old.FullchainPath, old.KeyPath, abandoned.FullchainPath, abandoned.KeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("transaction failure deleted recoverable certificate bytes")
		}
	}
}

func TestMigrateACMEPublicationFrom26AndDeleteCascade(t *testing.T) {
	dsn := freshSchemaDSN(t)
	st := openFresh(t, dsn)
	c := newACMECert(t, st, "pending", nil)
	if _, err := st.db.Exec(`DROP TABLE acme_apply_pending`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM schema_migrations WHERE version = 27`); err != nil {
		t.Fatal(err)
	}
	upgraded := openFresh(t, dsn)
	if got := certByID(t, upgraded, c.ID); got.ACMEStatus != "pending" || got.PrimaryDomain != c.PrimaryDomain {
		t.Fatal("migration changed certificate metadata")
	}
	now := time.Now().UTC()
	claimed := claimOnly(t, upgraded, ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}, c.ID)
	if claimed == nil {
		t.Fatal("upgraded certificate not claimed")
	}
	if err := upgraded.CompleteCertificateACME(context.Background(), claimed, func() (ACMEResult, error) {
		return publicationWrite(t, t.TempDir(), c.ID), nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(publicationTokens(t, upgraded)) != 1 {
		t.Fatal("upgraded publication not pending")
	}
	if err := upgraded.DeleteCertificate(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if len(publicationTokens(t, upgraded)) != 0 {
		t.Fatal("deleted certificate retained pending work")
	}
}
