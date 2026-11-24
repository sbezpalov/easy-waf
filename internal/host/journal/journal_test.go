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
	if !slices.Equal(args, []string{"journal", "--no-pager", "-n", "50", "-u", "haproxy.service", "--output", "short-iso"}) {
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
	const since = "2026-11-11 09:05:00.000000 UTC"
	args, err := buildHAProxyJournalArgs(since, BlockedLines, blocklog.JournalGrepBlocked)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"journal", "--no-pager", "-n", "5000", "-u", "haproxy.service",
		"--since", since, "--grep", blocklog.JournalGrepBlocked, "--output", "json"}
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

func TestReadHAProxyJournalUsesAbsoluteCutoff(t *testing.T) {
	// The same wall-clock time occurs twice when clocks fall back.
	for _, tc := range []struct {
		offset int
		want   string
	}{
		{-4 * 3600, "2026-11-01 05:30:00.123456 UTC"},
		{-5 * 3600, "2026-11-01 06:30:00.123456 UTC"},
	} {
		since := time.Date(2026, 11, 1, 1, 30, 0, 123456000, time.FixedZone("fixture", tc.offset))
		run := func(_ context.Context, args ...string) ([]byte, error) {
			idx := slices.Index(args, "--since")
			if idx < 0 || args[idx+1] != tc.want {
				t.Fatalf("expected cutoff %q, got %v", tc.want, args)
			}
			return nil, nil
		}
		if _, err := readHAProxyJournal(t.Context(), since, 2, PolicyLines, blocklog.JournalGrepPolicy, run); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadHAProxyJournalRetriesLegacyBrokerCutoff(t *testing.T) {
	since := time.Date(2026, 11, 1, 9, 5, 0, 0, time.Local)
	wantCutoffs := []string{since.UTC().Format("2006-01-02 15:04:05.000000 UTC"), "2026-11-01 09:05:00", "2026-11-01 09:05:00"}
	wantLimits := []string{"4", "4", "2"}
	replies := []error{errors.New("journal: invalid --since"), commandoutput.ErrLimit, nil}
	calls := 0
	run := func(_ context.Context, args ...string) ([]byte, error) {
		if calls >= len(replies) || args[7] != wantCutoffs[calls] || args[3] != wantLimits[calls] {
			t.Fatalf("unexpected journal request %d: %v", calls, args)
		}
		err := replies[calls]
		calls++
		if err != nil {
			return nil, err
		}
		return []byte("{\"MESSAGE\":\"fixture\"}\n"), nil
	}
	sample, err := readHAProxyJournal(t.Context(), since, 4, BlockedLines, blocklog.JournalGrepBlocked, run)
	if err != nil || calls != len(replies) || !sample.Truncated || sample.JSON == "" {
		t.Fatalf("journal sample %+v after %d calls, error %v", sample, calls, err)
	}
}

func TestBuildPolicyJournalArgs(t *testing.T) {
	const since = "2026-11-11 09:05:00.000000 UTC"
	if _, err := buildHAProxyJournalArgs(since, 200, blocklog.JournalGrepPolicy); err != nil {
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
	if _, err := buildHAProxyJournalArgs(since, 200, "arbitrary"); err == nil {
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
