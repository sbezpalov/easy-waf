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
	for _, name := range []string{"easy-waf-api.service", "easy-waf-acmed.service"} {
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
