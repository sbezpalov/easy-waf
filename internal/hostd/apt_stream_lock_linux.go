//go:build linux

package hostd

import (
	"os"
	"syscall"
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
	f, err := os.OpenFile("/var/lib/dpkg/lock-frontend", os.O_RDWR, 0)
	if err != nil {
		return true
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}
