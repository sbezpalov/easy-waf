// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestNormalizeRequestSecurityKeepsTogglesSentWithoutMode(t *testing.T) {
	sec := config.ApplicationSecurity{RateLimitEnabled: true, GeoIPEnabled: true, GeoIPCountryList: []string{"RU"}}
	normalizeRequestSecurity(&sec)
	if !sec.RateLimitEnabled || !sec.GeoIPEnabled || len(sec.GeoIPCountryList) != 1 {
		t.Fatalf("toggles were replaced: %+v", sec)
	}
	if sec.BasicWAFEnabled || sec.CrowdSecEnabled {
		t.Fatalf("defaults leaked into an explicit block: %+v", sec)
	}
	if sec.Mode != "custom" {
		t.Fatalf("mode = %q, want custom", sec.Mode)
	}
}

func TestNormalizeRequestSecurityEmptyBlockGetsDefaults(t *testing.T) {
	var sec config.ApplicationSecurity
	normalizeRequestSecurity(&sec)
	want := config.DefaultApplicationSecurity()
	if sec.Mode != want.Mode || sec.BasicWAFEnabled != want.BasicWAFEnabled || sec.CrowdSecEnabled != want.CrowdSecEnabled {
		t.Fatalf("got %+v, want defaults %+v", sec, want)
	}
}

func TestNormalizeRequestSecurityNamesMatchingPreset(t *testing.T) {
	sec := config.DefaultApplicationSecurity()
	sec.Mode = ""
	normalizeRequestSecurity(&sec)
	if sec.Mode != "balanced" {
		t.Fatalf("mode = %q, want balanced", sec.Mode)
	}
}

func TestWriteApplyRejectedStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"lock wait timed out", fmt.Errorf("acquire HAProxy apply lock: %w", context.DeadlineExceeded), http.StatusServiceUnavailable},
		{"validation failed", errors.New("validation failed: exit status 1"), http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeApplyRejected(rec, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestNonNil(t *testing.T) {
	var s []int
	if got := nonNil(s); got == nil || len(got) != 0 {
		t.Fatalf("nonNil(nil) = %#v", got)
	}
}
