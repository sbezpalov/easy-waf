// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hostd

import (
	"fmt"
	"os"
)

// openFileNoFollow is the Windows development fallback. It rejects an existing
// symlink immediately before opening the file. This has the same documented
// time-of-check/time-of-use limitation as the other non-Linux implementation;
// the appliance only ships the race-free Linux openat2 implementation.
func openFileNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, flags, mode)
}

// Windows has no numeric Unix UID/GID ownership to apply. The production Linux
// implementation performs the required chown operations; these no-ops only keep
// the non-shipping development fallback usable in Windows tests.
func setPathOwner(string, int, int) error {
	return nil
}

func setFileOwner(*os.File, int, int) error {
	return nil
}
