package api

import (
	"math"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// certificateSummaryMode maps stored mode to API values http-01 | dns-01 | manual.
func certificateSummaryMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "http-01", "http01":
		return "http-01"
	case "dns-01", "dns01":
		return "dns-01"
	default:
		return "manual"
	}
}

// BuildCertificateSummaryResponse aggregates certificate rows for GET /api/v1/certificates/summary.
// now should be UTC (e.g. time.Now().UTC()).
func BuildCertificateSummaryResponse(certs []config.Certificate, now time.Time) config.CertificateSummaryResponse {
	out := config.CertificateSummaryResponse{
		Total:        len(certs),
		Certificates: make([]config.CertificateSummaryEntry, 0, len(certs)),
	}
	for i := range certs {
		row := certificateSummaryEntry(&certs[i], now)
		out.Certificates = append(out.Certificates, row)
		switch row.Status {
		case "valid":
			out.Valid++
		case "expiring":
			out.ExpiringSoon++
		case "expired":
			out.Expired++
		}
	}
	return out
}

func certificateSummaryEntry(c *config.Certificate, now time.Time) config.CertificateSummaryEntry {
	acme := strings.ToLower(strings.TrimSpace(c.ACMEStatus))
	row := config.CertificateSummaryEntry{
		ID:            c.ID,
		PrimaryDomain: c.PrimaryDomain,
		Mode:          certificateSummaryMode(c.Mode),
	}
	if c.NotAfter != nil {
		t := *c.NotAfter
		row.NotAfter = &t
		d := int(math.Floor(t.Sub(now).Hours() / 24))
		row.DaysRemaining = &d
	}

	if c.NotAfter != nil && c.NotAfter.Before(now) {
		row.Status = "expired"
		return row
	}
	if acme == "pending" || acme == "issuing" {
		row.Status = "pending"
		return row
	}
	if acme == "failed" {
		row.Status = "pending"
		return row
	}
	if c.NotAfter == nil {
		row.Status = "pending"
		return row
	}
	d := int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
	if d < 30 {
		row.Status = "expiring"
	} else {
		row.Status = "valid"
	}
	return row
}
