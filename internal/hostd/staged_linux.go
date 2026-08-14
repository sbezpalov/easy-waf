//go:build linux

package hostd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"golang.org/x/sys/unix"
)

func openStagedFile(path string) (*os.File, error) {
	if !hostspec.ValidStagedPath(path) {
		return nil, fmt.Errorf("invalid staged path")
	}
	root := filepath.Clean(hostspec.StagingDirPrefix)
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	dirFD, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	fd, err := unix.Openat2(dirFD, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open staged file: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
