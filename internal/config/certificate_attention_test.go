// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestCertificateAttention(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	at := func(days int) *time.Time {
		v := now.Add(time.Duration(days) * 24 * time.Hour)
		return &v
	}
	for name, tc := range map[string]struct {
		cert Certificate
		want string
	}{
		"healthy":                 {Certificate{ACMEStatus: "ready", NotAfter: at(60)}, ""},
		"renewal not late yet":    {Certificate{ACMEStatus: "ready", NotAfter: at(25)}, ""},
		"exactly at the limit":    {Certificate{ACMEStatus: "ready", NotAfter: at(21)}, ""},
		"no certificate yet":      {Certificate{ACMEStatus: "pending"}, ""},
		"renewal should be done":  {Certificate{ACMEStatus: "ready", NotAfter: at(20)}, "expires in 20 days"},
		"being renewed, late":     {Certificate{ACMEStatus: "issuing", NotAfter: at(3)}, "expires in 3 days"},
		"failed, still valid":     {Certificate{ACMEStatus: "failed", NotAfter: at(60)}, "issuance or renewal failed"},
		"failed, first issuance":  {Certificate{ACMEStatus: "failed"}, "issuance or renewal failed"},
		"expired":                 {Certificate{ACMEStatus: "ready", NotAfter: at(-1)}, "expired"},
		"expired and failed":      {Certificate{ACMEStatus: "failed", NotAfter: at(-1)}, "expired"},
		"status in another case":  {Certificate{ACMEStatus: " FAILED ", NotAfter: at(60)}, "issuance or renewal failed"},
		"manual, close to expiry": {Certificate{Mode: "self-signed", ACMEStatus: "ready", NotAfter: at(5)}, "expires in 5 days"},
		"expires this instant":    {Certificate{ACMEStatus: "ready", NotAfter: at(0)}, "expired"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := CertificateAttention(&tc.cert, now); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
