// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/metrics"
)

func engineServer(t *testing.T, mutate func(*config.GlobalSettings)) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.DefaultSettings(dir)
	if mutate != nil {
		mutate(&cfg)
	}
	return &Server{Eng: engine.New(dir, nil, cfg)}
}

func TestGeoIPReloadRejectsMalformedBody(t *testing.T) {
	s := engineServer(t, func(g *config.GlobalSettings) { g.GeoIPProvider = "maxmind" })
	rec := httptest.NewRecorder()
	s.geoipReload(rec, httptest.NewRequest(http.MethodPost, "/api/v1/geoip/reload", strings.NewReader(`{"mmdb_path":`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGeoIPUploadErrorStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"body over limit", fmt.Errorf("mmdb: read input: %w", &http.MaxBytesError{Limit: 1}), http.StatusRequestEntityTooLarge},
		{"extracted over limit", fmt.Errorf("mmdb: %w", geoip.ErrMMDBTooLarge), http.StatusRequestEntityTooLarge},
		{"cannot create temp file", fmt.Errorf("mmdb: create temp file: %w", &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrPermission}), http.StatusInternalServerError},
		{"not a database", errors.New("mmdb: not a MaxMind database: invalid"), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := geoipUploadErrorStatus(tc.err); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCrowdSecRejectedLAPIURLIsReported(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_URL", "")
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	s := engineServer(t, func(g *config.GlobalSettings) { g.CrowdSecLAPIURL = "http://192.0.2.1:8080" })

	rec := httptest.NewRecorder()
	s.crowdsecStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/crowdsec", nil))
	var st crowdsec.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Reachable || !strings.Contains(st.LastMessage, "rejected") {
		t.Fatalf("status %+v, want the rejected URL reported", st)
	}

	rec = httptest.NewRecorder()
	s.crowdsecDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/crowdsec/decisions", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("decisions status %d (%s), want 502 instead of an empty list", rec.Code, rec.Body.String())
	}
}

func TestCrowdSecAddDecisionChecksIPBeforeLAPIURL(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_URL", "")
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	s := engineServer(t, func(g *config.GlobalSettings) { g.CrowdSecLAPIURL = "http://192.0.2.1:8080" })
	rec := httptest.NewRecorder()
	s.crowdsecAddDecision(rec, httptest.NewRequest(http.MethodPost, "/api/v1/integrations/crowdsec/decisions", strings.NewReader(`{"ip":""}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d (%s), want 400 for the missing IP", rec.Code, rec.Body.String())
	}
}

func TestCrowdSecDecisionErrorsIdentifyUpstreamAccessDenial(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			const privateBody = "upstream fixture detail"
			lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, privateBody, status)
			}))
			t.Cleanup(lapi.Close)
			t.Setenv("CROWDSEC_LAPI_URL", "")
			t.Setenv("CROWDSEC_LAPI_KEY", "fixture-key")
			t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", lapi.URL)
			s := engineServer(t, func(g *config.GlobalSettings) { g.CrowdSecLAPIURL = lapi.URL })
			actions := []struct {
				method, body string
				handler      http.HandlerFunc
			}{
				{http.MethodGet, "", s.crowdsecDecisions},
				{http.MethodPost, `{"ip":"192.0.2.1"}`, s.crowdsecAddDecision},
				{http.MethodDelete, "", s.crowdsecDeleteDecision},
			}
			want := "CrowdSec LAPI request failed."
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				want = "CrowdSec LAPI denied access. Check the configured API key and permissions."
			}
			for _, action := range actions {
				req := withURLParam(httptest.NewRequest(action.method, "/", strings.NewReader(action.body)), "id", "fixture")
				rec := httptest.NewRecorder()
				action.handler(rec, req)
				var detail map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusBadGateway || detail["error"] != want ||
					strings.Contains(rec.Body.String(), privateBody) || strings.Contains(rec.Body.String(), lapi.URL) {
					t.Fatalf("%s with upstream %d: %d %s", action.method, status, rec.Code, rec.Body)
				}
			}
		})
	}
}

func TestRefreshCrowdSecMetricsUsesEffectiveLAPIAndReportsFailure(t *testing.T) {
	const key = "metrics-fixture-key"
	var calls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != key || r.URL.Path != "/v1/decisions" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		switch calls.Add(1) {
		case 1:
			_, _ = fmt.Fprint(w, `{"data":[{"id":1},{"id":2}]}`)
		case 2:
			http.Error(w, "key denied", http.StatusForbidden)
		case 3:
			_, _ = fmt.Fprint(w, `null`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(lapi.Close)
	t.Setenv("CROWDSEC_LAPI_URL", lapi.URL)
	t.Setenv("CROWDSEC_LAPI_KEY", key)
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", lapi.URL)
	s := engineServer(t, func(g *config.GlobalSettings) {
		g.CrowdSecLAPIURL = "http://192.0.2.1:8080"
		g.CrowdSecLAPIKey = "stored-fixture-key"
	})
	s.Prom = metrics.NewPrometheusExporter()

	for _, step := range []struct {
		name, availability, count string
	}{
		{"wrapped sample", "1", "2"},
		{"access denied", "0", ""},
		{"empty after recovery", "1", "0"},
	} {
		t.Run(step.name, func(t *testing.T) {
			s.RefreshCrowdSecMetrics(t.Context())
			rec := httptest.NewRecorder()
			s.Prom.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, "easy_waf_crowdsec_decision_sample_available "+step.availability+"\n") {
				t.Fatalf("expected sample availability %s, got status %d and body:\n%s", step.availability, rec.Code, body)
			}
			const metric = "easy_waf_crowdsec_decisions_total "
			if step.count == "" {
				if strings.Contains(body, "\n"+metric) {
					t.Fatalf("unexpected decision count after LAPI failure:\n%s", body)
				}
			} else if !strings.Contains(body, "\n"+metric+step.count+"\n") {
				t.Fatalf("expected decision count %s, got:\n%s", step.count, body)
			}
		})
	}
}

func TestProfilesUseSnakeCase(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleProfiles(rec, httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil))
	var out map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	p, ok := out["balanced"]
	if !ok {
		t.Fatalf("no balanced profile in %v", out)
	}
	for _, k := range []string{"description", "rate_limit_rps", "connect_timeout_ms"} {
		if _, ok := p[k]; !ok {
			t.Errorf("missing key %q in %v", k, p)
		}
	}
	if _, ok := p["Description"]; ok {
		t.Error("PascalCase keys are still present")
	}
}
