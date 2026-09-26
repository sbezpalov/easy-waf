// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestBuildCertificateSummaryResponse_modes(t *testing.T) {
	if got := certificateSummaryMode("HTTP-01"); got != "http-01" {
		t.Fatalf("mode http-01: got %q", got)
	}
	if got := certificateSummaryMode("dns-01"); got != "dns-01" {
		t.Fatalf("mode dns-01: got %q", got)
	}
	if got := certificateSummaryMode("self-signed"); got != "manual" {
		t.Fatalf("mode manual: got %q", got)
	}
}

func TestBuildCertificateSummaryResponse_statuses(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	naFar := now.Add(90 * 24 * time.Hour)
	naSoon := now.Add(10 * 24 * time.Hour)
	naPast := now.Add(-5 * 24 * time.Hour)

	certs := []config.Certificate{
		{ID: "1", PrimaryDomain: "a.example", Mode: "http-01", ACMEStatus: "ready", NotAfter: &naFar},
		{ID: "2", PrimaryDomain: "b.example", Mode: "dns-01", ACMEStatus: "ready", NotAfter: &naSoon},
		{ID: "3", PrimaryDomain: "c.example", Mode: "http-01", ACMEStatus: "ready", NotAfter: &naPast},
		{ID: "4", PrimaryDomain: "d.example", Mode: "dns-01", ACMEStatus: "pending"},
		{ID: "5", PrimaryDomain: "e.example", Mode: "self-signed", ACMEStatus: "ready"},
	}
	s := BuildCertificateSummaryResponse(certs, now)
	if s.Total != 5 {
		t.Fatalf("total: got %d", s.Total)
	}
	if s.Valid != 1 || s.ExpiringSoon != 1 || s.Expired != 1 {
		t.Fatalf("counts valid=%d expiring=%d expired=%d", s.Valid, s.ExpiringSoon, s.Expired)
	}
	if len(s.Certificates) != 5 {
		t.Fatalf("rows: %d", len(s.Certificates))
	}
	byID := map[string]config.CertificateSummaryEntry{}
	for _, r := range s.Certificates {
		byID[r.ID] = r
	}
	if byID["1"].Status != "valid" {
		t.Fatalf("1: %q", byID["1"].Status)
	}
	if byID["2"].Status != "expiring" {
		t.Fatalf("2: %q", byID["2"].Status)
	}
	if byID["3"].Status != "expired" {
		t.Fatalf("3: %q", byID["3"].Status)
	}
	if byID["4"].Status != "pending" || byID["4"].Mode != "dns-01" {
		t.Fatalf("4: %+v", byID["4"])
	}
	if byID["5"].Status != "pending" {
		t.Fatalf("5: %q", byID["5"].Status)
	}
}

func TestBuildCertificateSummaryResponse_failedIsNotPending(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	stillValid := now.Add(20 * 24 * time.Hour)
	next := now.Add(40 * time.Minute)
	certs := []config.Certificate{
		// A renewal that failed while the old certificate still works.
		{ID: "r", PrimaryDomain: "r.example", Mode: "http-01", ACMEStatus: "failed", NotAfter: &stillValid,
			LastError: "acme: urn:ietf:params:acme:error:connection", ACMENextAttemptAt: &next},
		// A first issuance that never succeeded.
		{ID: "n", PrimaryDomain: "n.example", Mode: "dns-01", ACMEStatus: "failed", LastError: "dns timeout"},
	}
	s := BuildCertificateSummaryResponse(certs, now)
	if s.Failed != 2 || s.Valid != 0 || s.ExpiringSoon != 0 {
		t.Fatalf("counts failed=%d valid=%d expiring=%d", s.Failed, s.Valid, s.ExpiringSoon)
	}
	r := s.Certificates[0]
	if r.Status != "failed" || r.LastError == "" || r.NextAttemptAt == nil || !r.NextAttemptAt.Equal(next) {
		t.Fatalf("renewal row: %+v", r)
	}
	if s.Certificates[1].Status != "failed" || s.Certificates[1].NextAttemptAt != nil {
		t.Fatalf("issuance row: %+v", s.Certificates[1])
	}
}
