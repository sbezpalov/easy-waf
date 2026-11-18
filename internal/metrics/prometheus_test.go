// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
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

func TestHAProxyRuntimeMetricsTrackSampleAvailability(t *testing.T) {
	e := NewPrometheusExporter()
	check := func(want, absent []string) {
		t.Helper()
		rec := httptest.NewRecorder()
		e.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("scrape returned %d: %s", rec.Code, rec.Body)
		}
		body := rec.Body.String()
		for _, sample := range want {
			if !strings.Contains(body, "\neasy_waf_haproxy_"+sample+"\n") {
				t.Errorf("missing sample %q in:\n%s", sample, body)
			}
		}
		for _, sample := range absent {
			if strings.Contains(body, "\neasy_waf_haproxy_"+sample) {
				t.Errorf("unexpected sample %q in:\n%s", sample, body)
			}
		}
	}
	runtimeMetrics := []string{"frontend_req_rate{", "backend_sessions_current{", "backend_up{"}
	report := &HAProxyReport{
		Frontends: []FrontendStat{{Name: "fe_https", TotalReqHint: 100, ReqRate: 5}, {Name: "fe_removed", ReqRate: 3}},
		Backends:  []BackendStat{{Name: "be_app", SessionsCur: 2, Health: "healthy"}},
	}

	check([]string{"stats_available 0"}, runtimeMetrics)
	e.UpdateFromHAProxyReport(report)
	report.Frontends[0].TotalReqHint = 120
	e.UpdateFromHAProxyReport(report)
	check([]string{
		"stats_available 1",
		`frontend_requests_total{frontend="fe_https"} 20`,
		`frontend_req_rate{frontend="fe_https"} 5`,
		`frontend_req_rate{frontend="fe_removed"} 3`,
		`backend_sessions_current{backend="be_app"} 2`,
		`backend_up{backend="be_app"} 1`,
	}, nil)

	report.Error = "stats socket unavailable"
	e.UpdateFromHAProxyReport(report)
	check([]string{"stats_available 0", `frontend_requests_total{frontend="fe_https"} 20`}, runtimeMetrics)

	report.Error = ""
	report.Frontends[0].TotalReqHint = 130
	report.Frontends[0].ReqRate = 0
	e.UpdateFromHAProxyReport(report)
	report.Frontends = report.Frontends[:1]
	e.UpdateFromHAProxyReport(report)
	check([]string{
		"stats_available 1",
		`frontend_requests_total{frontend="fe_https"} 30`,
		`frontend_req_rate{frontend="fe_https"} 0`,
		`backend_up{backend="be_app"} 1`,
	}, []string{`frontend_req_rate{frontend="fe_removed"}`})
	e.UpdateFromHAProxyReport(nil)
	check([]string{"stats_available 0", `frontend_requests_total{frontend="fe_https"} 30`}, runtimeMetrics)
}

func TestCrowdSecDecisionSampleMetrics(t *testing.T) {
	e := NewPrometheusExporter()
	check := func(wantAvailable, wantCount float64) {
		t.Helper()
		families, err := e.reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		gauges := make(map[string]float64)
		for _, family := range families {
			if metric := family.GetMetric(); len(metric) == 1 && metric[0].GetGauge() != nil {
				gauges[family.GetName()] = metric[0].GetGauge().GetValue()
			}
		}
		available, ok := gauges["easy_waf_crowdsec_decision_sample_available"]
		if !ok || available != wantAvailable {
			t.Errorf("availability = %v (present %t), want %v", available, ok, wantAvailable)
		}
		count, ok := gauges["easy_waf_crowdsec_decisions_total"]
		if ok != (wantAvailable == 1) || count != wantCount {
			t.Errorf("count = %v (present %t), want %v (present %t)", count, ok, wantCount, wantAvailable == 1)
		}
	}
	check(0, 0)
	e.SetCrowdSecDecisionSampleSize(7)
	check(1, 7)
	e.ClearCrowdSecDecisionSample()
	check(0, 0)
	e.SetCrowdSecDecisionSampleSize(0)
	check(1, 0)
}
