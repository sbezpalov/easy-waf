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
	certDaysRemaining       *prometheus.GaugeVec
	crowdSecDecisions       prometheus.Gauge
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
		Help:      "1 if the backend aggregate health is not down, else 0.",
	}, []string{"backend"})
	e.certDaysRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "certificate_days_remaining",
		Help:      "Days until certificate NotAfter (UTC), when known.",
	}, []string{"domain", "mode"})
	e.crowdSecDecisions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "easy_waf",
		Name:      "crowdsec_decisions_total",
		Help:      "Number of decisions returned by the last LAPI sample (limit 100); not necessarily full CrowdSec inventory.",
	})
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
		e.haproxyFrontendReqRate,
		e.haproxyBackendSessions,
		e.haproxyBackendUp,
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

// UpdateFromHAProxyReport refreshes HAProxy-derived gauges and request counter deltas.
func (e *PrometheusExporter) UpdateFromHAProxyReport(rep *HAProxyReport) {
	if e == nil || rep == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

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

	e.haproxyBackendSessions.Reset()
	e.haproxyBackendUp.Reset()
	for _, be := range rep.Backends {
		bn := strings.TrimSpace(be.Name)
		if bn == "" {
			continue
		}
		e.haproxyBackendSessions.WithLabelValues(bn).Set(float64(be.SessionsCur))
		e.haproxyBackendUp.WithLabelValues(bn).Set(backendUpGauge(be))
	}
}

func backendUpGauge(be BackendStat) float64 {
	h := strings.ToLower(strings.TrimSpace(be.Health))
	if h == "down" {
		return 0
	}
	return 1
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

// SetCrowdSecDecisionSampleSize sets the CrowdSec gauge from the last LAPI decisions payload length.
func (e *PrometheusExporter) SetCrowdSecDecisionSampleSize(n int) {
	if e == nil {
		return
	}
	e.crowdSecDecisions.Set(float64(n))
}

// SetIPBLEntries sets local vs external IPBL gauges (see metric help for semantics).
func (e *PrometheusExporter) SetIPBLEntries(localEnabledRows, externalEnabledFeeds int) {
	if e == nil {
		return
	}
	e.ipblEntries.WithLabelValues("local").Set(float64(localEnabledRows))
	e.ipblEntries.WithLabelValues("external").Set(float64(externalEnabledFeeds))
}
