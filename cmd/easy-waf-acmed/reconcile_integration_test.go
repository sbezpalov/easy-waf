// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/acme"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
	"github.com/easy-waf/easy-waf/internal/testcert"
	"github.com/go-acme/lego/v4/certificate"
)

func reconcileFixture(t *testing.T) (*store.Store, *engine.Engine, string) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("ewacmed_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	dsn = u.String()
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	state := t.TempDir()
	cfg := config.DefaultSettings(state)
	cfg.IPBLExternalEnabled = false
	eng := engine.New(state, st, cfg)
	if err := eng.SaveSettings(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	return st, eng, dsn
}

func commitReconcileCertificate(t *testing.T, st *store.Store, eng *engine.Engine) store.ACMEApplyToken {
	t.Helper()
	c := &config.Certificate{PrimaryDomain: "reconcile.example.test", Mode: "http-01", ACMEStatus: "pending"}
	if err := st.UpsertCertificate(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteCertificate(context.Background(), c.ID) })
	path := filepath.Join(t.TempDir(), "fixture.pem")
	if err := testcert.WriteBundle(path, c.PrimaryDomain); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, key := pem.Decode(data)
	if block == nil {
		t.Fatal("fixture certificate missing")
	}
	now := time.Now().UTC()
	claimed, err := st.ClaimCertificatesACME(t.Context(), store.ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i := range claimed {
		if claimed[i].ID != c.ID {
			continue
		}
		found = true
		err = st.CompleteCertificateACME(t.Context(), &claimed[i], func() (store.ACMEResult, error) {
			full, keyPath, nb, na, err := acme.WriteCertificateResource(eng.StateDir, c.ID, &certificate.Resource{Certificate: pem.EncodeToMemory(block), PrivateKey: key})
			return store.ACMEResult{FullchainPath: full, KeyPath: keyPath, NotBefore: nb, NotAfter: na, Mode: "http-01"}, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatal("fixture certificate not claimed")
	}
	app := &config.Application{Name: "acme-" + c.ID, PublicHost: c.PrimaryDomain, BackendHost: "10.0.0.8", BackendPort: 8080, Profile: "balanced", Enabled: true, CertificateID: c.ID}
	if err := st.UpsertApplication(t.Context(), app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteApplication(context.Background(), app.ID) })
	tokens, err := st.PendingCertificateACMEApplies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if token.CertificateID == c.ID {
			return token
		}
	}
	t.Fatal("committed certificate has no apply intent")
	return store.ACMEApplyToken{}
}

func requirePendingToken(t *testing.T, st *store.Store, token store.ACMEApplyToken, want bool) {
	t.Helper()
	tokens, err := st.PendingCertificateACMEApplies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, got := range tokens {
		found = found || got == token
	}
	if found != want {
		t.Fatalf("pending token present=%v, want %v", found, want)
	}
}

func TestReconcileCommittedCertificateAfterRestart(t *testing.T) {
	st, eng, dsn := reconcileFixture(t)
	token := commitReconcileCertificate(t, st, eng)
	if legacyPendingForTest(t, eng.StateDir) {
		t.Fatal("new publication depends on legacy local marker")
	}
	// Reopen the database and discard the old engine/worker's in-memory state.
	reopened, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fresh := engine.New(eng.StateDir, reopened, eng.Settings())
	w := worker{eng: fresh}
	w.reconcile(t.Context())
	requirePendingToken(t, st, token, false)
	rows, err := st.ListCertificates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID != token.CertificateID {
			continue
		}
		chain, err := os.ReadFile(row.FullchainPath)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := os.ReadFile(filepath.Join(eng.StateDir, "certs", row.ID, "bundle.pem"))
		if err != nil || !bytes.HasPrefix(bundle, chain) {
			t.Fatal("edge bundle does not contain the committed certificate generation")
		}
	}
	before, err := st.ListConfigRevisions(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 {
		t.Fatal("restart did not apply committed certificate state")
	}
	// A crash after apply but before ack retries without another reload/revision.
	writeLegacyApplyPending(t, eng.StateDir)
	w.reconcile(t.Context())
	after, err := st.ListConfigRevisions(t.Context(), 1000)
	if err != nil || len(after) != len(before) || legacyPendingForTest(t, eng.StateDir) {
		t.Fatal("already-applied retry changed edge or lost legacy cleanup")
	}
}

func TestReconcileFailureCancellationAndSkipKeepIntent(t *testing.T) {
	st, eng, _ := reconcileFixture(t)
	token := commitReconcileCertificate(t, st, eng)
	writeLegacyApplyPending(t, eng.StateDir)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reconcileCertificateApplies(ctx, eng, "acme-test"); err == nil {
		t.Fatal("cancelled reconciliation succeeded")
	}
	requirePendingToken(t, st, token, true)
	w := worker{eng: eng}
	t.Setenv("EASY_WAF_ACME_SKIP_APPLY", "1")
	w.reconcile(t.Context())
	requirePendingToken(t, st, token, true)
	t.Setenv("EASY_WAF_ACME_SKIP_APPLY", "0")
	// A regular file where the managed config directory belongs fails apply.
	bad := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(bad, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := eng.Settings()
	original := cfg.HAProxyConfigPath
	cfg.HAProxyConfigPath = filepath.ToSlash(filepath.Join(bad, "haproxy.cfg"))
	eng.SetSettings(cfg)
	if err := eng.SaveSettings(t.Context()); err != nil {
		t.Fatal(err)
	}
	w.reconcile(t.Context())
	if w.lastTry.IsZero() || !legacyPendingForTest(t, eng.StateDir) {
		t.Fatal("failed apply lost retry/backoff or legacy intent")
	}
	requirePendingToken(t, st, token, true)
	cfg.HAProxyConfigPath = original
	eng.SetSettings(cfg)
	if err := eng.SaveSettings(t.Context()); err != nil {
		t.Fatal(err)
	}
	w.lastTry = time.Time{}
	w.reconcile(t.Context())
	requirePendingToken(t, st, token, false)
	if legacyPendingForTest(t, eng.StateDir) {
		t.Fatal("successful recovery kept legacy marker")
	}
}

func TestReconcileAcknowledgementFailureRetriesWithoutReload(t *testing.T) {
	st, eng, dsn := reconcileFixture(t)
	token := commitReconcileCertificate(t, st, eng)
	fault, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer fault.Close()
	for _, statement := range []string{
		`CREATE FUNCTION reject_acme_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected acknowledgement failure'; END $$`,
		`CREATE TRIGGER reject_acme_ack BEFORE DELETE ON acme_apply_pending FOR EACH ROW EXECUTE FUNCTION reject_acme_ack()`,
	} {
		if _, err := fault.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := reconcileCertificateApplies(t.Context(), eng, "acme-test")
	if err == nil || !applied {
		t.Fatal("acknowledgement failure must report an error after successful apply")
	}
	requirePendingToken(t, st, token, true)
	before, err := st.ListConfigRevisions(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fault.ExecContext(t.Context(), `DROP TRIGGER reject_acme_ack ON acme_apply_pending`); err != nil {
		t.Fatal(err)
	}
	fresh := engine.New(eng.StateDir, st, eng.Settings())
	applied, err = reconcileCertificateApplies(t.Context(), fresh, "acme-retry")
	if err != nil || applied {
		t.Fatal("retry after applied-but-unacknowledged publication reloaded or failed")
	}
	requirePendingToken(t, st, token, false)
	after, err := st.ListConfigRevisions(t.Context(), 1000)
	if err != nil || len(after) != len(before) {
		t.Fatal("acknowledgement retry created another revision")
	}
}
