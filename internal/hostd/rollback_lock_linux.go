// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// lockRollback serializes live-config mutations across broker connections and
// the separate systemd revert process. Lock the root-owned directory inode,
// avoiding a lock file that could be replaced while another process holds it.
// Interactive operations fail busy; the safety revert waits for apply to finish.
func lockRollback(wait bool) (func(), error) {
	fd, err := stateAnchorFD()
	if err != nil {
		return nil, err
	}
	flags := unix.LOCK_EX
	if !wait {
		flags |= unix.LOCK_NB
	}
	for {
		err = unix.Flock(fd, flags)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		if err == unix.EWOULDBLOCK {
			return nil, fmt.Errorf("network/firewall operation busy; retry after it completes")
		}
		return nil, fmt.Errorf("lock rollback state: %w", err)
	}
	return func() { _ = unix.Close(fd) }, nil
}
