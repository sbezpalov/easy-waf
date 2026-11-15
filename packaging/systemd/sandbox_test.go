// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemd_test

import (
	"os"
	"strings"
	"testing"
)

// sandboxKeys are the controls docs/SECURITY.md attributes to the API and to acmed.
var sandboxKeys = []string{
	"NoNewPrivileges=true",
	"PrivateTmp=true",
	"PrivateDevices=true",
	"ProtectHome=true",
	"ProtectKernelTunables=true",
	"ProtectKernelModules=true",
	"ProtectKernelLogs=true",
	"ProtectControlGroups=true",
	"ProtectClock=true",
	"ProtectHostname=true",
	"RestrictSUIDSGID=true",
	"RestrictNamespaces=true",
	"RestrictRealtime=true",
	"LockPersonality=true",
	"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	"SystemCallArchitectures=native",
	"CapabilityBoundingSet=",
	"AmbientCapabilities=",
}

func TestUnprivilegedUnitsAreSandboxed(t *testing.T) {
	for _, name := range []string{"easy-waf-api.service", "easy-waf-acmed.service", "easy-wafd.service"} {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, key := range sandboxKeys {
			if !strings.Contains(text, key) {
				t.Errorf("%s is missing %s", name, key)
			}
		}
	}
}

func TestLegacyDaemonUnitIsNotPackaged(t *testing.T) {
	body, err := os.ReadFile("../nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "easy-wafd") {
			t.Fatalf("legacy control-plane copy is packaged: %s", trim)
		}
	}
}
