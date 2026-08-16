package haproxy

import (
	"bytes"
	"regexp"
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
