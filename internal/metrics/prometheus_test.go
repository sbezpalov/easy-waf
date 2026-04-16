package metrics

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestPrometheusMetricsUpdate(t *testing.T) {
	e := NewPrometheusExporter()
	rep := &HAProxyReport{
		Frontends: []FrontendStat{
			{Name: "fe_https", TotalReqHint: 100, ReqRate: 5},
		},
		Backends: []BackendStat{
			{Name: "be_app", SessionsCur: 3, Health: "healthy"},
			{Name: "be_down", SessionsCur: 0, Health: "down"},
		},
	}
	e.UpdateFromHAProxyReport(rep)
	e.UpdateFromHAProxyReport(&HAProxyReport{
		Frontends: []FrontendStat{{Name: "fe_https", TotalReqHint: 127, ReqRate: 2}},
		Backends: []BackendStat{
			{Name: "be_app", SessionsCur: 4, Health: "healthy"},
		},
	})

	days := 30
	e.UpdateFromCertSummary(config.CertificateSummaryResponse{
		Certificates: []config.CertificateSummaryEntry{
			{PrimaryDomain: "a.example", Mode: "http-01", DaysRemaining: &days},
		},
	})
	e.UpdateFromAppStats([]config.Application{
		{Security: config.ApplicationSecurity{Mode: "balanced"}},
		{Security: config.ApplicationSecurity{Mode: "balanced"}},
		{Security: config.ApplicationSecurity{Mode: "full"}},
	})
	e.SetCrowdSecDecisionSampleSize(7)
	e.SetIPBLEntries(11, 2)
	e.IncApply()
	e.IncApplyError()

	mfs, err := e.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	for _, mf := range mfs {
		joined.WriteString(mf.GetName())
		joined.WriteByte('\n')
	}
	s := joined.String()
	for _, name := range []string{
		"easy_waf_haproxy_frontend_requests_total",
		"easy_waf_haproxy_frontend_req_rate",
		"easy_waf_haproxy_backend_sessions_current",
		"easy_waf_haproxy_backend_up",
		"easy_waf_certificate_days_remaining",
		"easy_waf_crowdsec_decisions_total",
		"easy_waf_ipbl_entries_total",
		"easy_waf_applications_total",
		"easy_waf_apply_total",
		"easy_waf_apply_errors_total",
	} {
		if !strings.Contains(s, name) {
			t.Fatalf("missing metric family %q in gather:\n%s", name, s)
		}
	}

	// Second HAProxy tick should have added a positive delta on the frontend counter.
	found := false
outer:
	for _, mf := range mfs {
		if mf.GetName() != "easy_waf_haproxy_frontend_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if m.GetCounter() != nil && m.GetCounter().GetValue() > 0 {
				found = true
				break outer
			}
		}
	}
	if !found {
		t.Fatal("expected fe_https request counter > 0 after second HAProxy update")
	}
}
