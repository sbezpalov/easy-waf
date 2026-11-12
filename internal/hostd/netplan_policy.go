// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Forbidden top-level renderer keys under network: — tunnels/WG bypass the
// nftables management guard and can lock the operator out of the LAN.
var netplanForbiddenKeyRE = regexp.MustCompile(`(?m)^\s{2,}(tunnels|wireguard|openvswitch|modems|nm-devices)\s*:`)

var netplanAllowedRendererRE = regexp.MustCompile(`(?m)^\s{2,}(ethernets|wifis|bridges|bonds|vlans|dummy-devices)\s*:`)

// validateNetplanYAML enforces a narrow netplan v2 allowlist before root apply.
func validateNetplanYAML(data []byte) error {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	trim := strings.TrimSpace(s)
	if trim == "" {
		return fmt.Errorf("netplan: empty yaml")
	}
	if !strings.Contains(s, "network:") {
		return fmt.Errorf("netplan: missing network key")
	}
	if !regexp.MustCompile(`(?m)^\s*version:\s*2\b`).MatchString(s) &&
		!regexp.MustCompile(`(?m)^\s{2,}version:\s*2\b`).MatchString(s) {
		return fmt.Errorf("netplan: version 2 required")
	}
	if netplanForbiddenKeyRE.MatchString(s) {
		return fmt.Errorf("netplan: tunnels/wireguard/openvswitch/modems are not allowed")
	}
	// Reject obvious VPN/tunnel device types under ethernets etc.
	if regexp.MustCompile(`(?m)^\s+type:\s*(wireguard|tunnel|vxlan|gre|ipip|sit|vti)\b`).MatchString(s) {
		return fmt.Errorf("netplan: tunnel device types are not allowed")
	}
	if !netplanAllowedRendererRE.MatchString(s) {
		return fmt.Errorf("netplan: no allowed interface section (ethernets/wifis/bridges/bonds/vlans)")
	}
	return nil
}

func validateNetplanFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return validateNetplanYAML(b)
}
