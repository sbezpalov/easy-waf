// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"testing"

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
