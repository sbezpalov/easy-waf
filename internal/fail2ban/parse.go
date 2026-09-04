// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package fail2ban

import (
	"regexp"
	"strings"
)

var jailListRE = regexp.MustCompile("(?m)^\\s*` - Jail list:\\s*(.+)$")

// parseStatusJails extracts jail names from `fail2ban-client status` output.
func parseStatusJails(out string) []string {
	m := jailListRE.FindStringSubmatch(out)
	if len(m) < 2 {
		return nil
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var jails []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			jails = append(jails, p)
		}
	}
	return jails
}

var bannedListRE = regexp.MustCompile("(?m)^\\s*` - Banned IP list:\\s*(.*)$")

// parseJailBannedIPs extracts banned IPs from `fail2ban-client status <jail>` output.
func parseJailBannedIPs(out string) []string {
	m := bannedListRE.FindStringSubmatch(out)
	if len(m) < 2 {
		return nil
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" {
		return []string{}
	}
	return strings.Fields(raw)
}
