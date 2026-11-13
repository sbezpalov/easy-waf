// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import "sync/atomic"

// SetBypassPeerCheckForTest disables SO_PEERCRED checks (unit tests dial as non-easy-waf uid).
func SetBypassPeerCheckForTest(v bool) {
	bypassPeerCheckForTest.Store(v)
}

var bypassPeerCheckForTest atomic.Bool

func peerCheckBypassed() bool {
	return bypassPeerCheckForTest.Load()
}
