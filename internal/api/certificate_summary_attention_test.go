// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestSummaryCarriesAttentionForAFailedRenewalStillValid(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	later := now.Add(60 * 24 * time.Hour)

	got := BuildCertificateSummaryResponse([]config.Certificate{
		{ID: "ok", PrimaryDomain: "ok.example", ACMEStatus: "ready", NotAfter: &later},
		{ID: "bad", PrimaryDomain: "bad.example", ACMEStatus: "failed", NotAfter: &later},
	}, now)

	if got.Certificates[0].Attention != "" {
		t.Fatalf("healthy certificate flagged: %q", got.Certificates[0].Attention)
	}
	if got.Certificates[1].Attention != "issuance or renewal failed" {
		t.Fatalf("attention %q", got.Certificates[1].Attention)
	}
}
