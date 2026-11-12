// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"testing"
	"time"

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
	args, err := buildBlockedArgs(since, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"journal", "--no-pager", "-n", "5000", "-u", "haproxy.service",
		"--since", "2026-11-11 09:05:00", "--grep", "[PL]R--", "--output", "json"}
	if len(args) != len(want) {
		t.Fatalf("args: %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}
