// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package blocklog reads the requests the edge refused out of HAProxy httplog
// lines. The frontends capture {host|rule}; see blockCapture in internal/haproxy.
package blocklog

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event is one refused request.
type Event struct {
	Time     time.Time `json:"time"`
	ClientIP string    `json:"client_ip"`
	Frontend string    `json:"frontend"`
	Backend  string    `json:"backend"`
	Status   int       `json:"status"`
	Host     string    `json:"host,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	Rule     string    `json:"rule"`
}

// %ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/... %sq/%bq {%hr} "%r"
var httplogRE = regexp.MustCompile(`^(\S+):\d+ \[[^\]]+\] (\S+) ([^/\s]+)/\S+ \S+ (\d{3}) \S+ \S+ \S+ (\S{4}) \S+ \S+(?: \{([^}]*)\})? "(.*)"$`)

const maxPath = 256

// ParseLine returns the event for one httplog message, or false when the line is
// not httplog or the edge did not refuse the request.
func ParseLine(msg string) (Event, bool) {
	m := httplogRE.FindStringSubmatch(strings.TrimSpace(msg))
	if m == nil {
		return Event{}, false
	}
	status, _ := strconv.Atoi(m[4])
	term := m[5]
	// PR: an http-request rule refused it. LR: HAProxy answered itself, which
	// is a refusal only for 4xx (redirects are LR too).
	if !(strings.HasPrefix(term, "PR") || (strings.HasPrefix(term, "LR") && status >= 400 && status < 500)) {
		return Event{}, false
	}
	ev := Event{
		ClientIP: m[1],
		Frontend: strings.TrimSuffix(m[2], "~"),
		Backend:  m[3],
		Status:   status,
	}
	if caps := m[6]; caps != "" {
		host, rule := caps, ""
		if i := strings.LastIndexByte(caps, '|'); i >= 0 {
			host, rule = caps[:i], caps[i+1:]
		}
		ev.Host, ev.Rule = host, rule
	}
	if f := strings.Fields(m[7]); len(f) >= 2 {
		ev.Method, ev.Path = f[0], stripOrigin(f[1])
	}
	if len(ev.Path) > maxPath {
		ev.Path = ev.Path[:maxPath] + "…"
	}
	if ev.Rule == "" {
		ev.Rule = fallbackRule(ev)
	}
	return ev, true
}

func stripOrigin(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return target
}

func fallbackRule(ev Event) string {
	switch {
	case ev.Status == 429:
		return "rate_limit"
	case ev.Backend == "bk_not_found" || ev.Backend == "bk_http_default":
		return "unknown_host"
	case ev.Status == 400:
		return "bad_request"
	default:
		return "other"
	}
}

type journalEntry struct {
	Message  json.RawMessage `json:"MESSAGE"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
}

// ParseJournal reads journalctl --output json lines. It returns the refused
// requests in input order and how many journal lines it read.
func ParseJournal(r io.Reader) (events []Event, lines int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		lines++
		var e journalEntry
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		ev, ok := ParseLine(journalMessage(e.Message))
		if !ok {
			continue
		}
		if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
			ev.Time = time.UnixMicro(us).UTC()
		}
		events = append(events, ev)
	}
	return events, lines
}

// journalMessage decodes MESSAGE, which journalctl prints as an array of bytes
// when it is not valid UTF-8.
func journalMessage(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		b = make([]byte, 0, len(ints))
		for _, v := range ints {
			if v >= 0 && v <= 255 {
				b = append(b, byte(v))
			}
		}
	}
	return strings.ToValidUTF8(string(b), "?")
}

// Count is one row of a top list.
type Count struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	Country string `json:"country,omitempty"`
}

// Summary aggregates refused requests.
type Summary struct {
	Total    int     `json:"total"`
	ByRule   []Count `json:"by_rule"`
	TopIPs   []Count `json:"top_ips"`
	TopHosts []Count `json:"top_hosts"`
}

// Summarize counts events by rule (all of them) and by client IP and host (the
// top n of each).
func Summarize(events []Event, n int) Summary {
	rules, ips, hosts := map[string]int{}, map[string]int{}, map[string]int{}
	for _, ev := range events {
		rules[ev.Rule]++
		ips[ev.ClientIP]++
		if ev.Host != "" {
			hosts[strings.ToLower(ev.Host)]++
		}
	}
	return Summary{
		Total:    len(events),
		ByRule:   top(rules, 0),
		TopIPs:   top(ips, n),
		TopHosts: top(hosts, n),
	}
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
