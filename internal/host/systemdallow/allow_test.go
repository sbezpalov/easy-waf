// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemdallow

import "testing"

func TestAllowedUnitAction(t *testing.T) {
	cases := []struct {
		unit, action string
		want         bool
	}{
		{"nftables.service", "restart", true},
		{"nftables.service", "reload", true},
		{"nftables.service", "start", true},
		{"nftables.service", "stop", false},
		{"nftables.service", "disable", false},
		{"haproxy.service", "stop", true},
		{"ssh.service", "restart", false},
		{"haproxy.service", "mask", false},
	}
	for _, c := range cases {
		if got := AllowedUnitAction(c.unit, c.action); got != c.want {
			t.Errorf("AllowedUnitAction(%q, %q) = %v, want %v", c.unit, c.action, got, c.want)
		}
	}
}
