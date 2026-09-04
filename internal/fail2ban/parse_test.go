// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package fail2ban

import "testing"

func TestParseStatusJails(t *testing.T) {
	out := "Status\n|- Number of jail:\t2\n` - Jail list:\tsshd, nginx-http-auth\n"
	jails := parseStatusJails(out)
	if len(jails) != 2 || jails[0] != "sshd" || jails[1] != "nginx-http-auth" {
		t.Fatalf("got %#v", jails)
	}
}

func TestParseJailBannedIPs(t *testing.T) {
	out := "Status for the jail: sshd\n|- Currently banned:\t2\n` - Banned IP list:\t203.0.113.1 198.51.100.2\n"
	ips := parseJailBannedIPs(out)
	if len(ips) != 2 || ips[0] != "203.0.113.1" {
		t.Fatalf("got %#v", ips)
	}
}

func TestParseJailBannedIPs_empty(t *testing.T) {
	out := "Status for the jail: sshd\n` - Banned IP list:\n"
	ips := parseJailBannedIPs(out)
	if ips == nil || len(ips) != 0 {
		t.Fatalf("expected empty slice, got %#v", ips)
	}
}
