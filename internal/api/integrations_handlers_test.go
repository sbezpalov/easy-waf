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
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/geoip"
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
