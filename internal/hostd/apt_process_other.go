// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import "errors"

// Native development tests can publish bookkeeping for their own subprocesses;
// Linux process epochs and recovered broker execution are not emulated here.
func captureAptProcessIdentity(pid int) (aptProcessIdentity, error) {
	return aptProcessIdentity{pid: pid}, nil
}

func resolveAptProcess(aptProcessIdentity) (*aptProcessIdentity, error) {
	return nil, errors.New("APT process recovery requires Linux")
}
