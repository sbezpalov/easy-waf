// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/metrics"
)

const (
	spikeWindow   = 5 * time.Minute
	spikeCooldown = 30 * time.Minute
	// confirmPolls is how many reads in a row must show a new server state
	// before it is announced: a reload briefly shows every server UP.
	confirmPolls = 2
)

// Monitor turns successive HAProxy stats reads into backend down/up and
// blocked-spike events. It is not safe for concurrent use.
type Monitor struct {
	servers        map[string]*serverState
	lastDenied     map[string]int64
	deniedInWindow int64
	windowStart    time.Time
	lastStatsAt    time.Time
	lastSpike      time.Time
}

type serverState struct {
	announced string
	candidate string
	n         int
}

func (s *serverState) resetCandidate() {
	s.candidate, s.n = "", 0
}

// NewMonitor returns a Monitor with no history: the first read sets the
// baseline and announces nothing.
func NewMonitor() *Monitor {
	return &Monitor{servers: map[string]*serverState{}}
}

// Observe compares rep with earlier reads. threshold is the blocked-spike
// alert level per 5 minutes; 0 turns that alert off.
func (m *Monitor) Observe(rep *metrics.HAProxyReport, now time.Time, threshold int) []Event {
	if rep == nil || rep.Error != "" {
		for _, state := range m.servers {
			state.resetCandidate()
		}
		return nil
	}
	var out []Event
	seen := map[string]bool{}
	for _, be := range rep.Backends {
		for _, sv := range be.Servers {
			key := be.Name + "/" + sv.Name
			seen[key] = true
			s := m.servers[key]
			st := serverHealth(sv)
			if st == "" {
				if s != nil {
					s.resetCandidate()
				}
				continue
			}
			if s == nil {
				m.servers[key] = &serverState{announced: st}
				continue
			}
			if st == s.announced {
				s.resetCandidate()
				continue
			}
			if st == s.candidate {
				s.n++
			} else {
				s.candidate, s.n = st, 1
			}
			if s.n < confirmPolls {
				continue
			}
			s.announced = st
			s.resetCandidate()
			out = append(out, backendEvent(be.Name, sv.Name, st))
		}
	}
	for k := range m.servers {
		if !seen[k] {
			delete(m.servers, k)
		}
	}

	if m.windowStart.IsZero() || now.Sub(m.lastStatsAt) > spikeWindow {
		// A long break in samples does not show when the counters increased.
		m.windowStart = now
		m.deniedInWindow = 0
		m.lastDenied = nil
	}
	nextDenied := make(map[string]int64, len(rep.Frontends))
	for _, fe := range rep.Frontends {
		// New frontends and counters that reset establish a fresh baseline.
		if previous, ok := m.lastDenied[fe.Name]; ok && fe.DeniedReq > previous {
			m.deniedInWindow += fe.DeniedReq - previous
		}
		nextDenied[fe.Name] = fe.DeniedReq
	}
	m.lastDenied, m.lastStatsAt = nextDenied, now
	if elapsed := now.Sub(m.windowStart); elapsed >= spikeWindow {
		delta := m.deniedInWindow
		if threshold > 0 && delta >= int64(threshold) && (m.lastSpike.IsZero() || now.Sub(m.lastSpike) >= spikeCooldown) {
			m.lastSpike = now
			out = append(out, Event{
				Kind:     "blocked_spike",
				Severity: SeverityWarning,
				Title:    "Spike of blocked requests",
				Text: fmt.Sprintf("The edge refused %d requests in the last %d minutes (alert threshold %d). See Logs / Audit, Blocked requests.",
					delta, int(elapsed.Round(time.Minute).Minutes()), threshold),
			})
		}
		m.deniedInWindow, m.windowStart = 0, now
	}
	return out
}

// serverHealth maps stable, confirmed server states to up or down.
func serverHealth(server metrics.ServerStat) string {
	if server.HealthCheckUnconfirmed() {
		return ""
	}
	switch strings.ToUpper(strings.TrimSpace(server.Status)) {
	case "UP":
		return "up"
	case "DOWN":
		return "down"
	}
	return ""
}

func backendEvent(backend, server, state string) Event {
	if state == "down" {
		text := fmt.Sprintf("HAProxy health checks mark server %s of backend %s DOWN: requests routed to it fail.", server, backend)
		if backend == "crowdsec-spoa" {
			text += " CrowdSec checks are skipped (fail open) until it is back."
		}
		return Event{Kind: "backend_down", Severity: SeverityCritical, Title: "Backend down: " + backend, Text: text}
	}
	return Event{
		Kind:     "backend_up",
		Severity: SeverityInfo,
		Title:    "Backend up: " + backend,
		Text:     fmt.Sprintf("Server %s of backend %s passes health checks again.", server, backend),
	}
}
