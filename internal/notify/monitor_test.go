// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

func report(status string, denied int64) *metrics.HAProxyReport {
	return &metrics.HAProxyReport{
		Frontends: []metrics.FrontendStat{{Name: "fe_https", DeniedReq: denied}},
		Backends:  []metrics.BackendStat{{Name: "bk_app", Servers: []metrics.ServerStat{{Name: "s1", Status: status}}}},
	}
}

func kinds(evs []Event) []string {
	if len(evs) == 0 {
		return nil
	}
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestMonitorBackendTransitionsAreConfirmed(t *testing.T) {
	m := NewMonitor()
	now := time.Unix(0, 0)
	step := func(status string) []string {
		now = now.Add(30 * time.Second)
		return kinds(m.Observe(report(status, 0), now, 0))
	}
	if got := step("DOWN"); got != nil {
		t.Fatalf("first read announces nothing: %v", got)
	}
	if got := step("UP"); got != nil {
		t.Fatalf("one UP read after a reload is not enough: %v", got)
	}
	if got := step("DOWN"); got != nil {
		t.Fatalf("back to the announced state: %v", got)
	}
	step("UP")
	if got := step("UP"); len(got) != 1 || got[0] != "backend_up" {
		t.Fatalf("confirmed up: %v", got)
	}
	step("DOWN 1/2") // transitional states are ignored
	step("DOWN")
	if got := step("DOWN"); len(got) != 1 || got[0] != "backend_down" {
		t.Fatalf("confirmed down: %v", got)
	}
	if got := step("no check"); got != nil {
		t.Fatalf("unchecked: %v", got)
	}
	if m.Observe(nil, now, 0) != nil || m.Observe(&metrics.HAProxyReport{Error: "socket"}, now, 0) != nil {
		t.Fatal("failed reads announce nothing")
	}
}

func TestMonitorBackendConfirmationRequiresConsecutiveReadings(t *testing.T) {
	checkReport := func(status, check string) *metrics.HAProxyReport {
		rep := report(status, 0)
		rep.Backends[0].Servers[0].CheckStatus = check
		return rep
	}
	for _, tc := range []struct {
		name     string
		baseline string
		target   string
		gap      *metrics.HAProxyReport
		want     string
	}{
		{"missing stats", "DOWN", "UP", nil, "backend_up"},
		{"socket error", "UP", "DOWN", &metrics.HAProxyReport{Error: "socket unavailable"}, "backend_down"},
		{"transitional status", "DOWN", "UP", report("UP 1/3", 0), "backend_up"},
		{"first check pending", "DOWN", "UP", checkReport("UP", "* INI"), "backend_up"},
		{"check result unknown", "UP", "DOWN", checkReport("DOWN", "UNK"), "backend_down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMonitor()
			now := time.Unix(0, 0)
			for _, sample := range []*metrics.HAProxyReport{report(tc.baseline, 0), report(tc.target, 0), tc.gap, report(tc.target, 0)} {
				if events := m.Observe(sample, now, 0); len(events) != 0 {
					t.Fatalf("unconfirmed transition: %+v", events)
				}
				now = now.Add(30 * time.Second)
			}
			if events := m.Observe(report(tc.target, 0), now, 0); len(events) != 1 || events[0].Kind != tc.want {
				t.Fatalf("expected %s after consecutive readings, got %+v", tc.want, events)
			}
		})
	}
}

func TestMonitorBackendConfirmationIgnoresCachedSample(t *testing.T) {
	m := NewMonitor()
	start := time.Unix(0, 0)
	initial := report("DOWN", 0)
	initial.CollectedAt = start
	m.Observe(initial, start, 0)

	next := report("UP", 0)
	next.CollectedAt = start.Add(30 * time.Second)
	m.Observe(next, next.CollectedAt, 0)
	copyOfNext := *next
	if got := m.Observe(&copyOfNext, next.CollectedAt.Add(time.Second), 0); len(got) != 0 {
		t.Fatalf("cached sample confirmed the state change: %+v", got)
	}
	copyOfNext.CollectedAt = next.CollectedAt.Add(30 * time.Second)
	if got := m.Observe(&copyOfNext, copyOfNext.CollectedAt, 0); len(got) != 1 || got[0].Kind != "backend_up" {
		t.Fatalf("expected confirmation from a new sample, got %+v", got)
	}
}

func TestMonitorBlockedSpike(t *testing.T) {
	m := NewMonitor()
	t0 := time.Unix(0, 0)
	m.Observe(report("UP", 100), t0, 50)
	if got := m.Observe(report("UP", 400), t0.Add(4*time.Minute), 50); got != nil {
		t.Fatalf("window not over: %v", got)
	}
	got := m.Observe(report("UP", 400), t0.Add(5*time.Minute), 50)
	if len(got) != 1 || got[0].Kind != "blocked_spike" {
		t.Fatalf("spike: %v", got)
	}
	if got := m.Observe(report("UP", 900), t0.Add(10*time.Minute), 50); got != nil {
		t.Fatalf("cooldown: %v", got)
	}
	// A reload resets HAProxy counters: that is a new baseline, not a spike.
	if got := m.Observe(report("UP", 10), t0.Add(40*time.Minute), 50); got != nil {
		t.Fatalf("reset: %v", got)
	}
	if got := m.Observe(report("UP", 70), t0.Add(45*time.Minute), 50); len(got) != 1 {
		t.Fatalf("spike after cooldown: %v", got)
	}
	if got := m.Observe(report("UP", 10000), t0.Add(80*time.Minute), 0); got != nil {
		t.Fatalf("threshold 0 is off: %v", got)
	}
}

func TestMonitorBlockedSpikeTracksFrontendsSeparately(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first []metrics.FrontendStat
		next  []metrics.FrontendStat
		want  bool
	}{
		{
			name:  "existing count on a new frontend is not a spike",
			first: []metrics.FrontendStat{{Name: "fe_http", DeniedReq: 12}},
			next:  []metrics.FrontendStat{{Name: "fe_http", DeniedReq: 13}, {Name: "fe_https", DeniedReq: 100}},
		},
		{
			name:  "a reset cannot hide another frontend's spike",
			first: []metrics.FrontendStat{{Name: "fe_http", DeniedReq: 900}, {Name: "fe_https", DeniedReq: 12}},
			next:  []metrics.FrontendStat{{Name: "fe_http", DeniedReq: 5}, {Name: "fe_https", DeniedReq: 62}},
			want:  true,
		},
		{
			name:  "a removed frontend cannot hide another frontend's spike",
			first: []metrics.FrontendStat{{Name: "fe_http", DeniedReq: 900}, {Name: "fe_https", DeniedReq: 12}},
			next:  []metrics.FrontendStat{{Name: "fe_https", DeniedReq: 62}},
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMonitor()
			now := time.Unix(0, 0)
			m.Observe(&metrics.HAProxyReport{Frontends: tc.first}, now, 50)
			events := m.Observe(&metrics.HAProxyReport{Frontends: tc.next}, now.Add(5*time.Minute), 50)
			if !tc.want {
				if len(events) != 0 {
					t.Fatalf("unexpected spike: %+v", events)
				}
				return
			}
			if len(events) != 1 || events[0].Kind != "blocked_spike" || !strings.Contains(events[0].Text, "refused 50 requests") {
				t.Fatalf("expected a spike of 50 requests, got %+v", events)
			}
		})
	}
}

func TestMonitorBlockedSpikeStartsNewWindowAfterStatsGap(t *testing.T) {
	m := NewMonitor()
	now := time.Unix(0, 0)
	m.Observe(report("UP", 12), now, 50)
	m.Observe(&metrics.HAProxyReport{Error: "socket unavailable"}, now.Add(time.Minute), 50)
	if events := m.Observe(report("UP", 600), now.Add(20*time.Minute), 50); len(events) != 0 {
		t.Fatalf("refusals over a long stats gap were reported as a spike: %+v", events)
	}
	if events := m.Observe(report("UP", 650), now.Add(25*time.Minute), 50); len(events) != 1 || events[0].Kind != "blocked_spike" {
		t.Fatalf("expected a spike in the new window, got %+v", events)
	}
}

func TestMonitorBlockedSpikeDoesNotUseCachedSampleToBridgeGap(t *testing.T) {
	m := NewMonitor()
	start := time.Unix(0, 0)
	initial := report("UP", 12)
	initial.CollectedAt = start
	m.Observe(initial, start, 50)
	m.Observe(initial, start.Add(4*time.Second), 50)

	next := report("UP", 600)
	next.CollectedAt = start.Add(5*time.Minute + time.Second)
	if got := m.Observe(next, next.CollectedAt, 50); len(got) != 0 {
		t.Fatalf("cached sample shortened the reported stats gap: %+v", got)
	}
}
