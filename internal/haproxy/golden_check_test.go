// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"regexp"
	"testing"
)

// statsSocketLine matches the first "stats socket <path> ..." in global (golden configs use one line).
var statsSocketLine = regexp.MustCompile(`(?m)^(\s*stats socket )(\S+)(.*)$`)

// caFileRef matches "ca-file <path>" on a server line.
var caFileRef = regexp.MustCompile(`(ca-file )(\S+)`)

// rewriteCAFilePathForHAProxyCheck points every ca-file reference at absPath.
//
// Golden fixtures record the operator-configured path (e.g. /etc/easy-waf/ca/lab.pem)
// because that is exactly what the renderer must emit. `haproxy -c` then tries to
// open it for real, so validating a golden config anywhere other than that one
// appliance — a clean container, CI — needs the reference redirected at a file
// that exists.
func rewriteCAFilePathForHAProxyCheck(cfg []byte, absPath string) []byte {
	return caFileRef.ReplaceAllFunc(cfg, func(m []byte) []byte {
		sub := caFileRef.FindSubmatch(m)
		if len(sub) != 3 {
			return m
		}
		out := make([]byte, 0, len(sub[1])+len(absPath))
		out = append(out, sub[1]...)
		return append(out, absPath...)
	})
}

// rewriteStatsSocketPathForHAProxyCheck replaces the socket path with absPath.
// HAProxy 3.x treats a relative first token as host:port and fails with "missing port specification";
// Unix sockets must use an absolute path (or abstract @…) for `haproxy -c`.
func rewriteStatsSocketPathForHAProxyCheck(cfg []byte, absPath string) []byte {
	return statsSocketLine.ReplaceAllFunc(cfg, func(m []byte) []byte {
		sub := statsSocketLine.FindSubmatch(m)
		if len(sub) != 4 {
			return m
		}
		out := make([]byte, 0, len(sub[1])+len(absPath)+len(sub[3]))
		out = append(out, sub[1]...)
		out = append(out, absPath...)
		out = append(out, sub[3]...)
		return out
	})
}

func TestRewriteStatsSocketPathForHAProxyCheck(t *testing.T) {
	got := rewriteStatsSocketPathForHAProxyCheck([]byte("\tstats socket rel.sock mode 660 level admin\n"), "/abs/s.sock")
	if want := "\tstats socket /abs/s.sock mode 660 level admin\n"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
