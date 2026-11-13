// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import "testing"

func TestNonLinuxPeerRequiresExplicitTestBypass(t *testing.T) {
	previous := peerCheckBypassed()
	t.Cleanup(func() { SetBypassPeerCheckForTest(previous) })
	SetBypassPeerCheckForTest(false)
	if err := allowPeer(nil); err == nil {
		t.Fatal("non-Linux peer was accepted without verifiable credentials")
	}
	SetBypassPeerCheckForTest(true)
	if err := allowPeer(nil); err != nil {
		t.Fatalf("explicit test bypass failed: %v", err)
	}
}
