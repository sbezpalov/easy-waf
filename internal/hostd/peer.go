// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

// SetBypassPeerCheckForTest disables SO_PEERCRED checks (unit tests dial as non-easy-waf uid).
func SetBypassPeerCheckForTest(v bool) {
	bypassPeerCheckForTest = v
}

var bypassPeerCheckForTest bool

func peerCheckBypassed() bool {
	return bypassPeerCheckForTest
}
