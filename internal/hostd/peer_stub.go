// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import "net"

func allowPeer(_ *net.UnixConn) error {
	return nil
}
