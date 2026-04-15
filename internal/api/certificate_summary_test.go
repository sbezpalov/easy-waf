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
