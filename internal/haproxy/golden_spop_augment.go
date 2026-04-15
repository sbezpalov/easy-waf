package haproxy

import "bytes"

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
