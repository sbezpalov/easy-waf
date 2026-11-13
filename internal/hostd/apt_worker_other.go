// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"context"
	"errors"
	"net"
)

func allowRootPeer(_ *net.UnixConn) error {
	if peerCheckBypassed() {
		return nil
	}
	return errors.New("APT worker peer verification requires Linux")
}

func validateAPTWorkerDirectory(_ string) error { return errors.New("APT worker requires Linux") }

func acquireAPTExecutionLease(_ context.Context, _ bool) (func() error, error) {
	return nil, errors.New("APT execution lease requires Linux")
}
