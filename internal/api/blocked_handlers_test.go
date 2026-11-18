// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestListPolicyMatches(t *testing.T) {
	original := readPolicyJournal
	t.Cleanup(func() { readPolicyJournal = original })
	now := time.Now()
	readPolicyJournal = func(context.Context, time.Time, int) (string, error) {
		return strings.Join([]string{
			journalLine(`192.0.2.1:1 [x] fe_http be_app/local 0/0/0/0/0 200 1 - - ---- 1/1/0/0/0 0/0 {app.example||policy-count:watch} "GET /?token=sensitive HTTP/1.1"`, now),
			journalLine(`192.0.2.1:2 [x] fe_http fe_http/<NOSRV> 0/-1/-1/-1/0 403 1 - - PR-- 1/1/0/0/0 0/0 {app.example|policy_block|policy-count:watch|policy-block:deny} "GET /?token=sensitive`, now.Add(time.Minute)),
			journalLine(`192.0.2.1:3 [x] fe_http be_app/local 0/0/0/0/0 200 1 - - ---- 1/1/0/0/0 0/0 {app.example||} "GET /{app.example|policy-count:forged} HTTP/1.1"`, now.Add(2*time.Minute)),
		}, "\n"), nil
	}
	rec := httptest.NewRecorder()
	(&Server{}).listPolicyMatches(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/policy-matches?period=1h&limit=1", nil))
	var resp struct {
		Truncated bool                 `json:"truncated"`
		Events    []blocklog.RuleEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || !resp.Truncated || len(resp.Events) != 1 || resp.Events[0].Status != 403 {
		t.Fatalf("unexpected response: %s", rec.Body)
	}
	matches := resp.Events[0].Matches
	if len(matches) != 2 || matches[0].ID != "watch" || matches[0].Action != "count" || matches[1].ID != "deny" || matches[1].Action != "block" {
		t.Fatalf("unexpected match order: %v", matches)
	}
	if strings.Contains(rec.Body.String(), "sensitive") || strings.Contains(rec.Body.String(), "192.0.2.1") {
		t.Fatalf("unexpected request contents in journal: %s", rec.Body)
	}
}

func journalLine(msg string, t time.Time) string {
	b, _ := json.Marshal(map[string]string{"MESSAGE": msg, "__REALTIME_TIMESTAMP": jsonInt(t.UnixMicro())})
	return string(b)
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestListBlocked(t *testing.T) {
	orig := readBlockedJournal
	t.Cleanup(func() { readBlockedJournal = orig })
	now := time.Now()
	var gotSince time.Time
	readBlockedJournal = func(_ context.Context, since time.Time, _ int) (string, error) {
		gotSince = since
		return strings.Join([]string{
			journalLine(`203.0.113.9:1 [x] fe_https~ fe_https/<NOSRV> 0/-1/-1/-1/0 403 1 - - PR-- 1/1/0/0/0 0/0 {a.example|sqli} "GET /?q=1 HTTP/1.1"`, now.Add(-2*time.Minute)),
			journalLine(`203.0.113.9:2 [x] fe_https~ fe_https/<NOSRV> 0/-1/-1/-1/0 403 1 - - PR-- 1/1/0/0/0 0/0 {a.example|geoip} "GET / HTTP/1.1"`, now.Add(-time.Minute)),
			journalLine(`198.51.100.1:3 [x] fe_http fe_http/<NOSRV> 0/-1/-1/-1/0 301 1 - - LR-- 1/1/0/0/0 0/0 {a.example|} "GET / HTTP/1.1"`, now),
		}, "\n"), nil
	}
	s := &Server{Eng: engine.New("", nil, config.GlobalSettings{})}

	rec := httptest.NewRecorder()
	s.listBlocked(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/blocked?period=1h", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if d := now.Sub(gotSince); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("since %v ago", d)
	}
	var resp blockedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Summary.Total != 2 || len(resp.Events) != 2 || resp.Events[0].Rule != "geoip" {
		t.Fatalf("newest first, redirects skipped: %+v", resp)
	}
	if len(resp.Summary.TopIPs) != 1 || resp.Summary.TopIPs[0].Count != 2 {
		t.Fatalf("top ips: %+v", resp.Summary.TopIPs)
	}

	rec = httptest.NewRecorder()
	s.listBlocked(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/blocked?period=30d", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad period: %d", rec.Code)
	}

	readBlockedJournal = func(context.Context, time.Time, int) (string, error) { return "", errors.New("broker down") }
	rec = httptest.NewRecorder()
	s.listBlocked(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/blocked", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("journal error: %d", rec.Code)
	}
}
