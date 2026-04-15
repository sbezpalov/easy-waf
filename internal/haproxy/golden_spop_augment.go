package haproxy

import "bytes"

// goldenSPOPBackendMarker is appended before a placeholder SPOP backend so `haproxy -c` can load
// golden configs: SPOE files use use-backend crowdsec-socket, which must exist in the main cfg (HAProxy 2.8+).
const goldenSPOPBackendMarker = "# -- easy-waf golden: SPOP backend for SPOE use-backend"

var goldenSPOPBackendFragment = []byte("\n" + goldenSPOPBackendMarker + `
backend crowdsec-socket
	mode spop
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
