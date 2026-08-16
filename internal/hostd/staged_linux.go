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
	anchorFD, err := stateAnchorFD()
	if err != nil {
		return nil, err
	}
	defer unix.Close(anchorFD)
	fd, err := openatBeneath(anchorFD, rel, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open staged file: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
