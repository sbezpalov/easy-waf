// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
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
