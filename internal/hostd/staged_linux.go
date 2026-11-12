// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openStagedFile opens a file the API staged for a privileged operation.
//
// The anchor is the state directory, not the staging directory. Opening
// /var/lib/easy-waf/staging directly resolved that component the normal way, and
// the easy-waf account owns it: RESOLVE_BENEATH constrains only what happens
// *below* an already-open descriptor, it cannot undo a symlink followed while
// obtaining that descriptor. `rm -rf staging && ln -s /etc staging` was
// therefore enough to make this read any root-owned file, with the contents
// echoed back to the caller through the nft or netplan parse error. Anchoring
// one level up closes it, because /var/lib is root-owned and the state directory
// entry itself cannot be swapped. See statefile.go.
func openStagedFile(path string) (*os.File, error) {
	rel, err := stateStagingRel(path)
	if err != nil {
		return nil, err
	}
	anchorFD, err := stagingAnchorFD()
	if err != nil {
		return nil, err
	}
	defer unix.Close(anchorFD)
	fd, err := openatBeneath(anchorFD, rel, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open staged file: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat staged file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("staged path is not a regular file")
	}
	return os.NewFile(uintptr(fd), path), nil
}
