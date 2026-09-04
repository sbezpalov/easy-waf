// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemd

import "testing"

func TestAllowedUnit_matchesPrivilegedScriptList(t *testing.T) {
	want := []string{
		"easy-waf-api.service",
		"easy-waf-acmed.service",
		"haproxy.service",
		"crowdsec.service",
		"crowdsec-spoa-bouncer.service",
		"fail2ban.service",
		"nftables.service",
		"postgresql.service",
	}
	if len(want) != len(AllowedUnits) {
		t.Fatalf("AllowedUnits len %d want %d", len(AllowedUnits), len(want))
	}
	for _, u := range want {
		if !AllowedUnit(u) {
			t.Fatalf("AllowedUnit(%q) false", u)
		}
	}
	if AllowedUnit("ssh.service") {
		t.Fatal("ssh.service must not be allowed")
	}
}

func TestAllowedAction_matchesPrivilegedScriptList(t *testing.T) {
	for _, a := range []string{"start", "stop", "restart", "reload", "enable", "disable", "try-restart"} {
		if !AllowedAction(a) {
			t.Fatalf("AllowedAction(%q) false", a)
		}
	}
	for _, a := range []string{"mask", "kill", "daemon-reload"} {
		if AllowedAction(a) {
			t.Fatalf("AllowedAction(%q) should be false", a)
		}
	}
}
