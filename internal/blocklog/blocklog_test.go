// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package blocklog

import (
	"strings"
	"testing"
	"time"
)

// Lines captured from HAProxy 2.8 with the frontend captures of the generated config.
const (
	lineDeny     = `172.17.0.1:49562 [11/Nov/2026:19:47:40.418] fe_https~ fe_https/<NOSRV> 0/-1/-1/-1/0 403 192 - - PR-- 1/1/0/0/0 0/0 {app.example|sqli} "GET /?q=union%20select HTTP/1.1"`
	lineReturn   = `172.17.0.1:49578 [11/Nov/2026:19:47:40.424] fe_https~ fe_https/<NOSRV> 0/-1/-1/-1/0 413 96 - - LR-- 1/1/0/0/0 0/0 {app.example|body_size} "POST /upload HTTP/1.1"`
	lineBackend  = `2001:db8::7:49586 [11/Nov/2026:19:47:40.429] fe_https~ bk_app_example/<NOSRV> 0/-1/-1/-1/0 429 225 - - PR-- 1/1/0/0/0 0/0 {app.example|} "GET /rl HTTP/1.1"`
	lineH2       = `172.17.0.1:39832 [11/Nov/2026:19:47:43.446] fe_https~ fe_https/<NOSRV> 0/-1/-1/-1/0 403 192 - - PR-- 1/1/0/0/0 0/0 {app.example|sensitive_path} "GET https://app.example/.git HTTP/2.0"`
	lineNotFound = `172.17.0.1:39833 [11/Nov/2026:19:47:43.446] fe_https~ bk_not_found/<NOSRV> 0/-1/-1/-1/0 404 192 - - PR-- 1/1/0/0/0 0/0 {other.example|} "GET / HTTP/1.1"`
	lineOK       = `172.17.0.1:49596 [11/Nov/2026:19:47:40.434] fe_https~ bk_app_example/s1 0/0/1/2/3 200 217 - - ---- 1/1/0/0/0 0/0 {app.example|} "GET /ok HTTP/1.1"`
	lineBackend4 = `172.17.0.1:49596 [11/Nov/2026:19:47:40.434] fe_https~ bk_app_example/s1 0/0/1/2/3 403 217 - - ---- 1/1/0/0/0 0/0 {app.example|} "GET /admin HTTP/1.1"`
	lineRedirect = `172.17.0.1:49597 [11/Nov/2026:19:47:40.434] fe_http fe_http/<NOSRV> 0/-1/-1/-1/0 301 100 - - LR-- 1/1/0/0/0 0/0 {app.example|} "GET / HTTP/1.1"`
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		line                     string
		ip, host, rule, path, fe string
		status                   int
	}{
		{lineDeny, "172.17.0.1", "app.example", "sqli", "/?q=union%20select", "fe_https", 403},
		{lineReturn, "172.17.0.1", "app.example", "body_size", "/upload", "fe_https", 413},
		{lineBackend, "2001:db8::7", "app.example", "rate_limit", "/rl", "fe_https", 429},
		{lineH2, "172.17.0.1", "app.example", "sensitive_path", "/.git", "fe_https", 403},
		{lineNotFound, "172.17.0.1", "other.example", "unknown_host", "/", "fe_https", 404},
	}
	for _, c := range cases {
		ev, ok := ParseLine(c.line)
		if !ok {
			t.Fatalf("not parsed: %s", c.line)
		}
		if ev.ClientIP != c.ip || ev.Host != c.host || ev.Rule != c.rule || ev.Path != c.path || ev.Frontend != c.fe || ev.Status != c.status {
			t.Fatalf("%s: got %+v", c.line, ev)
		}
	}
	for _, l := range []string{lineOK, lineBackend4, lineRedirect, "Proxy fe_https started.", ""} {
		if ev, ok := ParseLine(l); ok {
			t.Fatalf("%q parsed as refused: %+v", l, ev)
		}
	}
}

func TestParseJournal(t *testing.T) {
	in := strings.Join([]string{
		`{"MESSAGE":"` + strings.ReplaceAll(lineDeny, `"`, `\"`) + `","__REALTIME_TIMESTAMP":"1794426460418000"}`,
		`{"MESSAGE":"` + strings.ReplaceAll(lineOK, `"`, `\"`) + `","__REALTIME_TIMESTAMP":"1794426460434000"}`,
		`not json`,
		`{"MESSAGE":[49,46,50,46,51,46,52,58,49,32,91,120,93,32,102,101,32,102,101,47,60,78,79,83,82,86,62,32,48,32,52,48,51,32,48,32,45,32,45,32,80,82,45,45,32,48,32,48,32,123,104,124,103,101,111,105,112,125,32,34,71,69,84,32,47,32,72,84,84,80,47,49,46,49,34],"__REALTIME_TIMESTAMP":"1794426460000000"}`,
	}, "\n")
	ev, lines := ParseJournal(strings.NewReader(in))
	if lines != 4 || len(ev) != 2 {
		t.Fatalf("lines=%d events=%+v", lines, ev)
	}
	if !ev[0].Time.Equal(time.UnixMicro(1794426460418000)) || ev[0].Rule != "sqli" {
		t.Fatalf("event 0: %+v", ev[0])
	}
	if ev[1].ClientIP != "1.2.3.4" || ev[1].Rule != "geoip" {
		t.Fatalf("byte-array MESSAGE: %+v", ev[1])
	}
}

func TestSummarize(t *testing.T) {
	ev := []Event{
		{ClientIP: "a", Host: "X.example", Rule: "sqli"},
		{ClientIP: "a", Host: "x.example", Rule: "geoip"},
		{ClientIP: "b", Host: "y.example", Rule: "sqli"},
		{ClientIP: "c", Rule: "unknown_host"},
	}
	s := Summarize(ev, 2)
	if s.Total != 4 || len(s.ByRule) != 3 || s.ByRule[0] != (Count{Key: "sqli", Count: 2}) {
		t.Fatalf("by rule: %+v", s.ByRule)
	}
	if len(s.TopIPs) != 2 || s.TopIPs[0] != (Count{Key: "a", Count: 2}) || s.TopIPs[1].Key != "b" {
		t.Fatalf("top ips: %+v", s.TopIPs)
	}
	if len(s.TopHosts) != 2 || s.TopHosts[0] != (Count{Key: "x.example", Count: 2}) {
		t.Fatalf("top hosts: %+v", s.TopHosts)
	}
}
