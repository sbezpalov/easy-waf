// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package fail2ban

import "errors"

var (
	// ErrNotInstalled is returned when fail2ban-client is not on PATH.
	ErrNotInstalled = errors.New("fail2ban: fail2ban-client not found")
	// ErrDaemonDown is returned when ping does not get "pong".
	ErrDaemonDown = errors.New("fail2ban: daemon not responding")
	// ErrInvalidJail is returned when a jail name fails validation.
	ErrInvalidJail = errors.New("fail2ban: invalid jail name")
	// ErrInvalidIP is returned when an IP fails validation.
	ErrInvalidIP = errors.New("fail2ban: invalid IP address")
)
