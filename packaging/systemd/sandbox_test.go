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

func TestMCPDaemonHasSeparateIdentityAndTLSConfig(t *testing.T) {
	body, err := os.ReadFile("easy-waf-mcpd.service")
	if err != nil {
		t.Fatal(err)
	}
	lines := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		lines[strings.TrimSpace(line)] = true
	}
	for _, line := range []string{
		"ConditionPathExists=/etc/easy-waf-mcp.env",
		"ConditionPathExists=/etc/easy-waf-mcp-ca.pem",
		"EnvironmentFile=/etc/easy-waf-mcp.env",
		"Environment=EASY_WAF_MCP_API_CA_FILE=/etc/easy-waf-mcp-ca.pem",
		"DynamicUser=true", "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true",
		"RestrictAddressFamilies=AF_INET AF_INET6", "IPAddressDeny=any", "IPAddressAllow=localhost",
		"InaccessiblePaths=-/etc/easy-waf -/var/lib/easy-waf -/run/easy-waf -/etc/easy-waf-mcp.env",
	} {
		if !lines[line] {
			t.Errorf("MCP unit is missing %q", line)
		}
	}
	for line := range lines {
		if strings.HasPrefix(line, "User=") || strings.HasPrefix(line, "Group=") ||
			strings.HasPrefix(line, "SupplementaryGroups=") || strings.Contains(line, "/etc/easy-waf/easy-waf.env") {
			t.Errorf("MCP unit shares appliance credentials: %q", line)
		}
	}
}
