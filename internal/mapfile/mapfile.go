// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package mapfile holds helpers shared by the generators that write HAProxy map
// files (ipbl, ipwl, blockedua, geoip).
package mapfile

import "strings"

// HasEntries reports whether data contains at least one non-comment line.
//
// Every map generator needs this before enabling its ACL — an empty map file
// makes HAProxy reject the configuration that references it. It lived as an
// identical copy in two packages; keeping one implementation means the
// definition of "empty" cannot drift between them.
func HasEntries(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true
	}
	return false
}
