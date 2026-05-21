//go:build !linux

package hostd

func emitDpkgLockHint(func(string) error) {}
func dpkgLockBusy() bool                  { return false }
