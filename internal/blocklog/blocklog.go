// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package blocklog reads edge refusals and publication rule matches from HAProxy
// httplog. The frontends capture the host, refusal reason and policy matches.
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
const httplogPrefix = `^(\S+):\d+ \[[^\]]+\] (\S+) ([^/\s]+)/\S+ \S+ (\d{3}) \S+ \S+ \S+ (\S{4}) \S+ \S+`

// HAProxy can clip the end of the request line after writing the refusal
// metadata. The opening quote marks the point where that optional data starts.
var httplogRE = regexp.MustCompile(httplogPrefix + `(?: \{([^}]*)\})? "(.*)$`)

// The request line follows the captures. Keep matches even if HAProxy
// truncates a long request target at the end of the log message.
var policyLogRE = regexp.MustCompile(httplogPrefix + ` \{([^}]*)\} "`)

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
		fields := strings.SplitN(caps, "|", 3)
		ev.Host = fields[0]
		if len(fields) > 1 {
			ev.Rule = fields[1]
		}
	}
	request, closed := strings.CutSuffix(m[7], `"`)
	f := strings.Fields(request)
	if len(f) >= 2 {
		ev.Method, ev.Path = f[0], stripOrigin(f[1])
	}
	if len(ev.Path) > maxPath {
		ev.Path = ev.Path[:maxPath] + "…"
	} else if ev.Path != "" && !closed && len(f) == 2 {
		ev.Path += "…"
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
	lines = scanJournal(r, func(message string, at time.Time) {
		if ev, ok := ParseLine(message); ok {
			ev.Time = at
			events = append(events, ev)
		}
	})
	return events, lines
}

// RuleMatch is one configured policy rule that matched a request.
type RuleMatch struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

// RuleEvent reports policy matches in execution order and the final status.
// It deliberately excludes request targets and header values.
type RuleEvent struct {
	Time    time.Time   `json:"time"`
	Host    string      `json:"host"`
	Status  int         `json:"status"`
	Matches []RuleMatch `json:"matches"`
}

var policyCaptureRE = regexp.MustCompile(`^policy-(count|block|pass):([a-z0-9][a-z0-9_-]{0,31})$`)

// ParseRuleJournal is independent of the final HTTP status: Count can match
// a successful request or one later rejected by another rule.
func ParseRuleJournal(r io.Reader) (events []RuleEvent, lines int) {
	lines = scanJournal(r, func(message string, at time.Time) {
		m := policyLogRE.FindStringSubmatch(strings.TrimSpace(message))
		if m == nil {
			return
		}
		captures := strings.Split(m[6], "|")
		if len(captures) < 3 || captures[0] == "" {
			return
		}
		status, _ := strconv.Atoi(m[4])
		event := RuleEvent{Time: at, Host: captures[0], Status: status}
		for _, capture := range captures[2:] {
			if match := policyCaptureRE.FindStringSubmatch(capture); match != nil {
				event.Matches = append(event.Matches, RuleMatch{ID: match[2], Action: match[1]})
			}
		}
		if len(event.Matches) > 0 {
			events = append(events, event)
		}
	})
	return events, lines
}

func scanJournal(r io.Reader, visit func(string, time.Time)) (lines int) {
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
		var at time.Time
		if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
			at = time.UnixMicro(us).UTC()
		}
		visit(journalMessage(e.Message), at)
	}
	return lines
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
