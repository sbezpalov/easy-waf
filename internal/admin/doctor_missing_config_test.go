// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestMissingConfigDoesNotHideTheStatsSocketCheck(t *testing.T) {
	if _, err := exec.LookPath("haproxy"); err != nil {
		t.Skip("haproxy not installed")
	}
	checks := checkHAProxy(t.TempDir())
	want := config.DefaultSettings("").HAProxyStatsSocketPath
	var sawConfig, sawSocket bool
	for _, c := range checks {
		switch c.Name {
		case "Configuration File":
			sawConfig = true
			if c.Status != StatusWarn {
				t.Fatalf("missing config status %s: %s", c.Status, c.Message)
			}
		case "Stats Socket":
			sawSocket = true
			if c.Status != StatusWarn || !strings.Contains(c.Message, want) || strings.Contains(c.Message, "/run/haproxy/admin.sock") {
				t.Fatalf("stats check %+v, want a warning naming %s", c, want)
			}
		}
	}
	if !sawConfig || !sawSocket {
		t.Fatalf("missing config hid a check: config=%v socket=%v %+v", sawConfig, sawSocket, checks)
	}
}
