// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"bufio"
	"os"
	"regexp"
	"runtime"
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

// ReportHostname reads the current static name on Linux. Sandboxed services
// using ProtectHostname may retain their original kernel hostname after a rename.
func ReportHostname() string {
	if runtime.GOOS == "linux" {
		if name := staticReportHostname("/etc/hostname"); name != "" {
			return name
		}
	}
	name, _ := os.Hostname()
	return name
}

func staticReportHostname(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		name := strings.TrimSpace(lines.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		// A systemd hostname template needs host-specific expansion. Use the
		// kernel hostname rather than reporting the literal question marks.
		if len(name) > 64 {
			return ""
		}
		for _, label := range strings.Split(strings.ToLower(name), ".") {
			if !dnsLabel.MatchString(label) {
				return ""
			}
		}
		return name
	}
	return ""
}
