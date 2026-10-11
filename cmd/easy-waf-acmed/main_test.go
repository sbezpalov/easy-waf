// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestCertsNotLive(t *testing.T) {
	applied := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	before, after := applied.Add(-time.Minute), applied.Add(time.Minute)
	cert := func(status string, updated time.Time) config.Certificate {
		return config.Certificate{ACMEStatus: status, UpdatedAt: updated}
	}
	cases := []struct {
		name      string
		certs     []config.Certificate
		lastApply *time.Time
		want      bool
	}{
		{"applied after the renewal", []config.Certificate{cert("ready", before)}, &applied, false},
		{"renewed after the last apply", []config.Certificate{cert("ready", before), cert("ready", after)}, &applied, true},
		{"failed or issuing rows do not count", []config.Certificate{cert("failed", after), cert("issuing", after)}, &applied, false},
		{"ready certificate, never applied", []config.Certificate{cert("ready", before)}, nil, true},
		{"nothing ready, never applied", []config.Certificate{cert("pending", before)}, nil, false},
		{"no certificates", nil, &applied, false},
	}
	for _, tc := range cases {
		if got := certsNotLive(tc.certs, tc.lastApply); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
