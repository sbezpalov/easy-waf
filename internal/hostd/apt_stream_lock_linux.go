// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// dpkgLockBusyHook overrides lock detection in tests (linux only).
var dpkgLockBusyHook func() bool

func emitDpkgLockHint(emit func(string) error) {
	if dpkgLockBusy() {
		_ = emit("==> apt is locked by another process (apt-daily/unattended-upgrades); waiting up to 120s ...")
	}
}

func dpkgLockBusy() bool {
	if dpkgLockBusyHook != nil {
		return dpkgLockBusyHook()
	}
	return dpkgLockFileBusy("/var/lib/dpkg/lock-frontend")
}

func dpkgLockFileBusy(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return true
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return true
	}
	// APT/dpkg use POSIX record locks, independent of flock on Linux. Query
	// without taking a competing lock: this is only an advisory user hint.
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(unix.SEEK_SET)}
	if err := unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lock); err != nil {
		return true
	}
	return lock.Type != unix.F_UNLCK
}
