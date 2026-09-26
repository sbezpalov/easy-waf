// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// newACMECert inserts a throwaway certificate row and removes it at cleanup.
func newACMECert(t *testing.T, st *Store, status string, notAfter *time.Time) *config.Certificate {
	t.Helper()
	ctx := context.Background()
	c := &config.Certificate{
		PrimaryDomain: "acme-" + time.Now().Format("150405.000000000") + ".example",
		Mode:          "http-01",
		ACMEStatus:    status,
		NotAfter:      notAfter,
	}
	if err := st.UpsertCertificate(ctx, c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteCertificate(context.Background(), c.ID) })
	return c
}

func claimOnly(t *testing.T, st *Store, w ACMEClaimWindow, id string) *config.Certificate {
	t.Helper()
	w.Limit = 1000
	got, err := st.ClaimCertificatesACME(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	var found *config.Certificate
	for i := range got {
		if got[i].ID == id {
			found = &got[i]
		} else {
			// Leave rows other tests own untouched.
			_ = st.FailCertificateACME(context.Background(), &got[i], "", w.Now)
		}
	}
	return found
}

func certByID(t *testing.T, st *Store, id string) config.Certificate {
	t.Helper()
	all, err := st.ListCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("certificate %s not found", id)
	return config.Certificate{}
}

func TestACMEFailedRowIsRetriedAfterBackoff(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	c := newACMECert(t, st, "pending", nil)
	now := time.Now().UTC()
	w := ACMEClaimWindow{Now: now, RenewBefore: now.Add(30 * 24 * time.Hour), StaleIssuing: time.Hour}

	claimed := claimOnly(t, st, w, c.ID)
	if claimed == nil || claimed.ACMEStatus != "issuing" {
		t.Fatalf("pending row not claimed: %+v", claimed)
	}
	if again := claimOnly(t, st, w, c.ID); again != nil {
		t.Fatal("a freshly claimed row was claimed twice")
	}

	next := now.Add(10 * time.Minute)
	if err := st.FailCertificateACME(ctx, claimed, "dns timeout", next); err != nil {
		t.Fatal(err)
	}
	row := certByID(t, st, c.ID)
	if row.ACMEStatus != "failed" || row.ACMEAttempts != 1 || row.LastError != "dns timeout" || row.ACMENextAttemptAt == nil {
		t.Fatalf("after failure: %+v", row)
	}

	if early := claimOnly(t, st, w, c.ID); early != nil {
		t.Fatal("failed row claimed before its retry time")
	}
	w.Now = next.Add(time.Second)
	retry := claimOnly(t, st, w, c.ID)
	if retry == nil || retry.ACMEAttempts != 1 {
		t.Fatalf("failed row not retried after backoff: %+v", retry)
	}

	// A manual "Request issue" resets the counter.
	row.ACMEStatus = "pending"
	if err := st.UpsertCertificate(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if got := certByID(t, st, c.ID); got.ACMEAttempts != 0 || got.ACMENextAttemptAt != nil {
		t.Fatalf("manual request did not reset retry state: %+v", got)
	}
}

func TestACMECompleteUpdatesOnlyWorkerColumnsAndHonoursClaim(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	c := newACMECert(t, st, "pending", nil)
	now := time.Now().UTC()
	w := ACMEClaimWindow{Now: now, RenewBefore: now, StaleIssuing: time.Hour}
	claimed := claimOnly(t, st, w, c.ID)
	if claimed == nil {
		t.Fatal("not claimed")
	}

	// The operator edits the row during issuance: the worker's result is discarded
	// and its write callback never runs.
	edited := certByID(t, st, c.ID)
	edited.SAN = []string{"extra.example"}
	edited.ACMEStatus = "pending"
	if err := st.UpsertCertificate(ctx, &edited); err != nil {
		t.Fatal(err)
	}
	wrote := false
	err := st.CompleteCertificateACME(ctx, claimed, func() (ACMEResult, error) {
		wrote = true
		return ACMEResult{}, nil
	})
	if !errors.Is(err, ErrACMEClaimLost) || wrote {
		t.Fatalf("stale claim: err=%v wrote=%v", err, wrote)
	}
	if err := st.FailCertificateACME(ctx, claimed, "x", now); !errors.Is(err, ErrACMEClaimLost) {
		t.Fatalf("stale fail: %v", err)
	}

	claimed = claimOnly(t, st, w, c.ID)
	if claimed == nil {
		t.Fatal("edited row not claimed again")
	}
	nb, na := now.Add(-time.Hour), now.Add(90*24*time.Hour)
	if err := st.CompleteCertificateACME(ctx, claimed, func() (ACMEResult, error) {
		return ACMEResult{FullchainPath: "/tmp/f.pem", KeyPath: "/tmp/k.pem", NotBefore: nb, NotAfter: na, Mode: "http-01"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got := certByID(t, st, c.ID)
	if got.ACMEStatus != "ready" || got.FullchainPath != "/tmp/f.pem" || got.NotAfter == nil ||
		len(got.SAN) != 1 || got.SAN[0] != "extra.example" || got.LastError != "" {
		t.Fatalf("after complete: %+v", got)
	}
}

func TestACMEStaleIssuingAndRenewalAreClaimed(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	soon := now.Add(5 * 24 * time.Hour)
	renew := newACMECert(t, st, "ready", &soon)
	stuck := newACMECert(t, st, "pending", nil)

	w := ACMEClaimWindow{Now: now, RenewBefore: now.Add(30 * 24 * time.Hour), StaleIssuing: time.Hour}
	if claimOnly(t, st, w, renew.ID) == nil {
		t.Fatal("certificate inside the renewal window not claimed")
	}
	if claimOnly(t, st, w, stuck.ID) == nil {
		t.Fatal("pending row not claimed")
	}
	// The worker "crashes": the row stays issuing. Within the window it is left alone...
	if claimOnly(t, st, w, stuck.ID) != nil {
		t.Fatal("in-flight row reclaimed too early")
	}
	// ...and after it the row is taken over.
	w.Now = now.Add(2 * time.Hour)
	if claimOnly(t, st, w, stuck.ID) == nil {
		t.Fatal("stale issuing row not reclaimed")
	}
}
