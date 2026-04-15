package haproxy

import (
	"bytes"
	"regexp"
)

// statsSocketLine matches the first "stats socket <path> ..." in global (golden configs use one line).
var statsSocketLine = regexp.MustCompile(`(?m)^(\s*stats socket )(\S+)(.*)$`)

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

// goldenSPOPBackendMarker is appended before a placeholder backend so `haproxy -c` can load
// golden configs: SPOE files use use-backend crowdsec-socket, which must exist in the main cfg (HAProxy 2.8+).
//
// Use mode tcp (not spop): some distro packages (e.g. Alma/RHEL HAProxy 3.x) are built without the
// spop proxy mode, then `mode spop` makes `haproxy -c` fail. A TCP backend is enough for syntax check.
const goldenSPOPBackendMarker = "# -- easy-waf golden: SPOP backend for SPOE use-backend"

var goldenSPOPBackendFragment = []byte("\n" + goldenSPOPBackendMarker + `
backend crowdsec-socket
	mode tcp
	balance roundrobin
	server spoa-placeholder 127.0.0.1:9000
`)

func augmentGoldenHAProxyCfgForHaproxyCheck(raw []byte) []byte {
	if bytes.Contains(raw, []byte(goldenSPOPBackendMarker)) {
		return raw
	}
	out := bytes.TrimSuffix(raw, []byte("\n"))
	return append(out, goldenSPOPBackendFragment...)
}
