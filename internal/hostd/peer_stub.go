// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"fmt"
	"net"
)

func allowPeer(_ *net.UnixConn) error {
	if peerCheckBypassed() {
		return nil
	}
	return fmt.Errorf("host broker peer verification requires Linux")
}
