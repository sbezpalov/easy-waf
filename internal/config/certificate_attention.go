// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"time"
)

// CertificateAttentionDays is when a certificate close to expiry becomes a
// problem. acmed renews 30 days ahead, so by now renewal has been failing for
// over a week, and a manual certificate needs replacing soon.
const CertificateAttentionDays = 21

// CertificateAttention says why an operator has to look at a certificate, or
// returns "" when nothing is wrong.
func CertificateAttention(c *Certificate, now time.Time) string {
	if c.NotAfter != nil && !c.NotAfter.After(now) {
		return "expired"
	}
	if strings.EqualFold(strings.TrimSpace(c.ACMEStatus), "failed") {
		return "issuance or renewal failed"
	}
	if c.NotAfter == nil {
		return ""
	}
	if days := int(c.NotAfter.Sub(now).Hours() / 24); days < CertificateAttentionDays {
		return fmt.Sprintf("expires in %d days", days)
	}
	return ""
}
