// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/commandoutput"
	hostsystemd "github.com/easy-waf/easy-waf/internal/host/systemd"
)

func TestBuildJournalArgs_allowlistedUnit(t *testing.T) {
	args, err := buildJournalArgs(Query{Unit: "haproxy", Lines: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) < 4 || args[len(args)-2] != "-u" || args[len(args)-1] != "haproxy.service" {
		t.Fatalf("args: %v", args)
	}
}

func TestBuildJournalArgs_rejectsBadUnit(t *testing.T) {
	_, err := buildJournalArgs(Query{Unit: "ssh"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildJournalArgs_requiresUnit(t *testing.T) {
	_, err := buildJournalArgs(Query{Lines: 10})
	if err == nil {
		t.Fatal("expected error when unit is empty")
	}
}

func TestBuildJournalArgs_rejectsInjectionSince(t *testing.T) {
	_, err := buildJournalArgs(Query{Since: "today; rm -rf /"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildJournalArgs_haproxyOnSystemdList(t *testing.T) {
	if !hostsystemd.AllowedUnit("haproxy.service") {
		t.Fatal("haproxy.service must be allowed")
	}
}

func TestBuildBlockedArgs(t *testing.T) {
	since := time.Date(2026, 11, 11, 9, 5, 0, 0, time.Local)
	args, err := buildHAProxyJournalArgs(since, BlockedLines, blocklog.JournalGrepBlocked)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"journal", "--no-pager", "-n", "5000", "-u", "haproxy.service",
		"--since", "2026-11-11 09:05:00", "--grep", blocklog.JournalGrepBlocked, "--output", "json"}
	if len(args) != len(want) {
		t.Fatalf("args: %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestReadHAProxyJournalFitsBrokerOutputBudget(t *testing.T) {
	const entries = 3000
	var requested []int
	padding := strings.Repeat("a", 1800)
	run := func(_ context.Context, args ...string) ([]byte, error) {
		count, err := strconv.Atoi(args[3])
		if err != nil {
			t.Fatal(err)
		}
		requested = append(requested, count)
		var capture commandoutput.Capture
		for i := entries - 1; i >= entries-min(entries, count); i-- {
			line := fmt.Sprintf(`{"MESSAGE":"entry-%04d %s"}`+"\n", i, padding)
			if _, err := io.WriteString(capture.Stdout(), line); err != nil {
				t.Fatal(err)
			}
		}
		out, _, err := capture.Result()
		return out, err
	}
	sample, err := readHAProxyJournal(t.Context(), time.Now(), 0, BlockedLines, blocklog.JournalGrepBlocked, run)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(requested, []int{5000, 2500, 1250}) {
		t.Fatalf("requests: %v", requested)
	}
	if !sample.Truncated || strings.Count(sample.JSON, "\n") != 1250 ||
		!strings.HasPrefix(sample.JSON, `{"MESSAGE":"entry-2999 `) ||
		!strings.HasSuffix(sample.JSON, fmt.Sprintf(`{"MESSAGE":"entry-1750 %s"}`+"\n", padding)) {
		t.Fatal("expected an explicitly truncated sample of the newest complete entries")
	}
}

func TestReadHAProxyJournalPropagatesUnrelatedFailures(t *testing.T) {
	failure := errors.New("journal failed")
	run := func(_ context.Context, args ...string) ([]byte, error) {
		if args[3] != "1000" {
			t.Fatalf("unexpected retry or invalid policy cap: %v", args)
		}
		return nil, failure
	}
	if _, err := readHAProxyJournal(t.Context(), time.Now(), 0, PolicyLines, blocklog.JournalGrepPolicy, run); !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}
}

func TestBuildPolicyJournalArgs(t *testing.T) {
	if _, err := buildHAProxyJournalArgs(time.Now(), 200, blocklog.JournalGrepPolicy); err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(blocklog.JournalGrepPolicy)
	const prefix = `192.0.2.1:1 [x] fe_http be_app/local 0/0/0/0/0 200 1 - - ---- 1/1/0/0/0 0/0 `
	if !pattern.MatchString(prefix + `{app.example|||policy-count:watch|} "GET / HTTP/1.1"`) {
		t.Fatal("journal pattern missed a policy capture after an empty slot")
	}
	for _, tail := range []string{
		`{app.example||} "GET /{app.example||policy-count:watch} HTTP/1.1"`,
		`{app.example|policy-count:watch|} "GET / HTTP/1.1"`,
		`{app.example||policy-count:watch.extra|} "GET / HTTP/1.1"`,
	} {
		if pattern.MatchString(prefix + tail) {
			t.Errorf("journal pattern matched outside a valid policy capture: %s", tail)
		}
	}
	if _, err := buildHAProxyJournalArgs(time.Now(), 200, "arbitrary"); err == nil {
		t.Fatal("unapproved grep pattern was accepted")
	}
}

func TestBlockedGrepUsesTerminationField(t *testing.T) {
	pattern := regexp.MustCompile(blocklog.JournalGrepBlocked)
	const start = `192.0.2.1:1 [x] fe_http fe_http/<NOSRV> 0/-1/-1/-1/0 `
	const request = ` 1/1/0/0/0 0/0 {app.example|} "GET /PR-- HTTP/1.1"`
	for _, tc := range []struct {
		fields string
		match  bool
	}{
		{"403 1 - - PR--", true},
		{"403 1 - - PRVN", true},
		{"413 1 - - LR--", true},
		{"301 1 - - LR--", false},
		{"200 1 - - ----", false},
		{"403 1 - - ----", false},
	} {
		tail := request
		if tc.match {
			tail = strings.ReplaceAll(tail, "PR--", "fixture")
		}
		if got := pattern.MatchString(start + tc.fields + tail); got != tc.match {
			t.Errorf("fields %q: matched = %t, want %t", tc.fields, got, tc.match)
		}
	}
}
