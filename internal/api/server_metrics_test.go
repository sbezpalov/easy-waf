// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/metrics"
)

func TestMetricsEndpointDisabled(t *testing.T) {
	eng := &engine.Engine{
		Settings: config.GlobalSettings{
			PrometheusEnabled:      false,
			ManagementAllowedCIDRs: []string{"127.0.0.0/8"},
		},
	}
	s := &Server{
		Eng:       eng,
		JWTSecret: []byte("test-secret"),
		Prom:      metrics.NewPrometheusExporter(),
	}
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when prometheus disabled, got %d", resp.StatusCode)
	}
}

func TestMetricsEndpointEnabled(t *testing.T) {
	eng := &engine.Engine{
		Settings: config.GlobalSettings{
			PrometheusEnabled:      true,
			ManagementAllowedCIDRs: []string{"127.0.0.0/8"},
		},
	}
	s := &Server{
		Eng:       eng,
		JWTSecret: []byte("test-secret"),
		Prom:      metrics.NewPrometheusExporter(),
	}
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "# HELP easy_waf") {
		t.Fatalf("expected prometheus exposition, got:\n%s", body)
	}
}
