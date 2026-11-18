// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"strings"
	"sync"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusExporter holds easy-waf metrics in a dedicated registry (not prometheus.DefaultRegisterer).
type PrometheusExporter struct {
	mu  sync.Mutex
	reg *prometheus.Registry

	haproxyFrontendReqTotal *prometheus.CounterVec
	haproxyFrontendReqRate  *prometheus.GaugeVec
	haproxyBackendSessions  *prometheus.GaugeVec
	haproxyBackendUp        *prometheus.GaugeVec
	haproxyStatsAvailable   bool
	certDaysRemaining       *prometheus.GaugeVec
	crowdSecDecisions       *crowdSecDecisionCollector
	ipblEntries             *prometheus.GaugeVec
	appsTotal               *prometheus.GaugeVec
	applyTotal              prometheus.Counter
	applyErrors             prometheus.Counter

	feReqSeen map[string]bool
	feReqPrev map[string]int64
}

// NewPrometheusExporter registers all easy_waf_* series on a fresh registry.
func NewPrometheusExporter() *PrometheusExporter {
	reg := prometheus.NewRegistry()
	e := &PrometheusExporter{
		reg:       reg,
		feReqSeen: make(map[string]bool),
		feReqPrev: make(map[string]int64),
	}
	e.haproxyFrontendReqTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "easy_waf",
		Name:      "haproxy_frontend_requests_total",
		Help:      "HAProxy frontend response totals; increases by the delta of TotalReqHint between control-plane refreshes (15s).",
	}, []string{"frontend"})
	e.haproxyFrontendReqRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "haproxy_frontend_req_rate",
		Help:      "HAProxy frontend current request rate (req/s) from show stat.",
	}, []string{"frontend"})
	e.haproxyBackendSessions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "haproxy_backend_sessions_current",
		Help:      "HAProxy backend current sessions (scur).",
	}, []string{"backend"})
	e.haproxyBackendUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "haproxy_backend_up",
		Help:      "1 for healthy or degraded backends, 0 for unavailable backends. Unknown health is omitted.",
	}, []string{"backend"})
	e.certDaysRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "certificate_days_remaining",
		Help:      "Days until certificate NotAfter (UTC), when known.",
	}, []string{"domain", "mode"})
	e.crowdSecDecisions = &crowdSecDecisionCollector{
		countDesc: prometheus.NewDesc("easy_waf_crowdsec_decisions_total",
			"Number of decisions returned by the last successful LAPI sample (requested limit 100).", nil, nil),
		availabilityDesc: prometheus.NewDesc("easy_waf_crowdsec_decision_sample_available",
			"1 when the latest CrowdSec decisions sample succeeded, 0 before the first sample or after a failure.", nil, nil),
	}
	e.ipblEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "ipbl_entries_total",
		Help:      "IP blacklist row counts: local = enabled DB CIDR rows; external = enabled external feed URLs configured.",
	}, []string{"type"})
	e.appsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "applications_total",
		Help:      "Applications in the store grouped by security.mode.",
	}, []string{"mode"})
	e.applyTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "easy_waf",
		Name:      "apply_total",
		Help:      "Successful HAProxy apply operations (engine apply after validation).",
	})
	e.applyErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "easy_waf",
		Name:      "apply_errors_total",
		Help:      "Failed apply attempts (API POST /api/v1/apply returning an error).",
	})
	reg.MustRegister(
		e.haproxyFrontendReqTotal,
		haproxyRuntimeCollector{
			exporter: e,
			availability: prometheus.NewDesc("easy_waf_haproxy_stats_available",
				"1 if the latest HAProxy stats sample succeeded, 0 before the first sample or after a failure.", nil, nil),
			gauges: []*prometheus.GaugeVec{e.haproxyFrontendReqRate, e.haproxyBackendSessions, e.haproxyBackendUp},
		},
		e.certDaysRemaining,
		e.crowdSecDecisions,
		e.ipblEntries,
		e.appsTotal,
		e.applyTotal,
		e.applyErrors,
	)
	return e
}

// Handler serves Prometheus text exposition for this registry.
func (e *PrometheusExporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{Registry: e.reg})
}

// IncApply records one successful apply.
func (e *PrometheusExporter) IncApply() { e.applyTotal.Inc() }

// IncApplyError records one failed apply attempt.
func (e *PrometheusExporter) IncApplyError() { e.applyErrors.Inc() }

// UpdateFromHAProxyReport refreshes HAProxy metrics. An unavailable sample
// clears current gauges while retaining cumulative counters and their baselines.
func (e *PrometheusExporter) UpdateFromHAProxyReport(rep *HAProxyReport) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.haproxyFrontendReqRate.Reset()
	e.haproxyBackendSessions.Reset()
	e.haproxyBackendUp.Reset()
	e.haproxyStatsAvailable = rep != nil && rep.Error == ""
	if !e.haproxyStatsAvailable {
		return
	}

	for _, fe := range rep.Frontends {
		name := strings.TrimSpace(fe.Name)
		if name == "" {
			continue
		}
		cur := fe.TotalReqHint
		if !e.feReqSeen[name] {
			e.feReqSeen[name] = true
			e.feReqPrev[name] = cur
		} else {
			prev := e.feReqPrev[name]
			if cur < prev {
				// HAProxy restart or stats reset — do not emit a negative jump.
				e.feReqPrev[name] = cur
			} else {
				delta := cur - prev
				e.feReqPrev[name] = cur
				if delta > 0 {
					e.haproxyFrontendReqTotal.WithLabelValues(name).Add(float64(delta))
				}
			}
		}
		e.haproxyFrontendReqRate.WithLabelValues(name).Set(float64(fe.ReqRate))
	}

	for _, be := range rep.Backends {
		bn := strings.TrimSpace(be.Name)
		if bn == "" {
			continue
		}
		e.haproxyBackendSessions.WithLabelValues(bn).Set(float64(be.SessionsCur))
		switch be.Health {
		case "healthy", "degraded":
			e.haproxyBackendUp.WithLabelValues(bn).Set(1)
		case "down":
			e.haproxyBackendUp.WithLabelValues(bn).Set(0)
		}
	}
}

type haproxyRuntimeCollector struct {
	exporter     *PrometheusExporter
	availability *prometheus.Desc
	gauges       []*prometheus.GaugeVec
}

func (c haproxyRuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.availability
	for _, gauge := range c.gauges {
		gauge.Describe(ch)
	}
}

func (c haproxyRuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	// A refresh replaces the gauges, so a scrape keeps its original values
	// even if the next refresh starts before Prometheus encodes them.
	c.exporter.mu.Lock()
	defer c.exporter.mu.Unlock()
	var available float64
	if c.exporter.haproxyStatsAvailable {
		available = 1
	}
	ch <- prometheus.MustNewConstMetric(c.availability, prometheus.GaugeValue, available)
	for _, gauge := range c.gauges {
		gauge.Collect(ch)
	}
}

// UpdateFromCertSummary sets per-certificate days remaining (resets stale label pairs each refresh).
func (e *PrometheusExporter) UpdateFromCertSummary(summary config.CertificateSummaryResponse) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.certDaysRemaining.Reset()
	for i := range summary.Certificates {
		c := summary.Certificates[i]
		dom := strings.TrimSpace(c.PrimaryDomain)
		if dom == "" {
			dom = strings.TrimSpace(c.ID)
		}
		mode := strings.TrimSpace(c.Mode)
		if mode == "" {
			mode = "unknown"
		}
		if c.DaysRemaining == nil {
			continue
		}
		e.certDaysRemaining.WithLabelValues(dom, mode).Set(float64(*c.DaysRemaining))
	}
}

// UpdateFromAppStats sets applications_total by security mode.
func (e *PrometheusExporter) UpdateFromAppStats(apps []config.Application) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appsTotal.Reset()
	counts := map[string]int{}
	for i := range apps {
		m := strings.TrimSpace(apps[i].Security.Mode)
		if m == "" {
			m = "unknown"
		}
		counts[m]++
	}
	for mode, n := range counts {
		e.appsTotal.WithLabelValues(mode).Set(float64(n))
	}
}

// SetCrowdSecDecisionSampleSize records a successful CrowdSec decisions sample.
func (e *PrometheusExporter) SetCrowdSecDecisionSampleSize(n int) {
	if e == nil {
		return
	}
	e.crowdSecDecisions.set(n, true)
}

// ClearCrowdSecDecisionSample marks the CrowdSec decision count as unavailable.
func (e *PrometheusExporter) ClearCrowdSecDecisionSample() {
	if e != nil {
		e.crowdSecDecisions.set(0, false)
	}
}

// CrowdSec sample size and availability are collected from the same snapshot.
type crowdSecDecisionCollector struct {
	mu               sync.Mutex
	size             int
	available        bool
	countDesc        *prometheus.Desc
	availabilityDesc *prometheus.Desc
}

func (c *crowdSecDecisionCollector) set(size int, available bool) {
	c.mu.Lock()
	c.size = size
	c.available = available
	c.mu.Unlock()
}

func (c *crowdSecDecisionCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.countDesc
	ch <- c.availabilityDesc
}

func (c *crowdSecDecisionCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	size, available := c.size, c.available
	c.mu.Unlock()

	var readiness float64
	if available {
		readiness = 1
		ch <- prometheus.MustNewConstMetric(c.countDesc, prometheus.GaugeValue, float64(size))
	}
	ch <- prometheus.MustNewConstMetric(c.availabilityDesc, prometheus.GaugeValue, readiness)
}

// SetIPBLEntries sets local vs external IPBL gauges (see metric help for semantics).
func (e *PrometheusExporter) SetIPBLEntries(localEnabledRows, externalEnabledFeeds int) {
	if e == nil {
		return
	}
	e.ipblEntries.WithLabelValues("local").Set(float64(localEnabledRows))
	e.ipblEntries.WithLabelValues("external").Set(float64(externalEnabledFeeds))
}
