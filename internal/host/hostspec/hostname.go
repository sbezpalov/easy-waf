// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"regexp"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var numericHostEnd = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)

// ValidManagementName accepts canonical ASCII DNS names suitable for HTTPS URLs.
func ValidManagementName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return !numericHostEnd.MatchString(labels[len(labels)-1]) && name != "localhost" && !strings.HasSuffix(name, ".localhost")
}

// ValidHostName also observes Linux's 64-byte limit for the system hostname.
func ValidHostName(name string) bool { return len(name) <= 64 && ValidManagementName(name) }
