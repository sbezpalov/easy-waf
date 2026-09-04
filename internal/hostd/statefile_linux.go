// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// stateAnchorFD opens the state directory itself, refusing a symlink at that
// final component. Every other resolution happens relative to this descriptor.
func stateAnchorFD() (int, error) {
	fd, err := unix.Open(stateDir,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: stateDir, Err: err}
	}
	return fd, nil
}

// stateSubdirFD resolves relDir beneath the anchor without traversing a
// symlink, optionally creating the components. relDir may be "." for the state
// directory itself. The caller closes the returned descriptor.
//
// Mkdirat cannot be tricked into landing outside the tree: if the name already
// exists as a symlink it returns EEXIST, and the openat2 that follows refuses to
// traverse it — so the call fails closed instead of following the link.
func stateSubdirFD(relDir string, create bool, mode os.FileMode) (int, error) {
	dirFD, err := stateAnchorFD()
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(filepath.Clean(relDir), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if create {
			if err := unix.Mkdirat(dirFD, part, uint32(mode.Perm())); err != nil && err != unix.EEXIST {
				unix.Close(dirFD)
				return -1, fmt.Errorf("mkdir %s under %s: %w", part, stateDir, err)
			}
		}
		next, err := openatBeneath(dirFD, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		unix.Close(dirFD)
		if err != nil {
			return -1, &os.PathError{Op: "open", Path: filepath.Join(stateDir, relDir), Err: err}
		}
		dirFD = next
	}
	return dirFD, nil
}

// stateOpenFile opens an existing file under the state directory for reading.
func stateOpenFile(path string) (*os.File, error) {
	rel, err := stateRel(path)
	if err != nil {
		return nil, err
	}
	dirFD, err := stateSubdirFD(filepath.Dir(rel), false, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	fd, err := openatBeneath(dirFD, filepath.Base(rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// stateCreateFile creates or truncates a file under the state directory.
func stateCreateFile(path string, mode os.FileMode) (*os.File, error) {
	rel, err := stateRel(path)
	if err != nil {
		return nil, err
	}
	dirFD, err := stateSubdirFD(filepath.Dir(rel), true, 0o750)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	fd, err := openatBeneath(dirFD, filepath.Base(rel),
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, uint64(mode.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	// openat2 applies mode only when it creates the file; an existing one keeps
	// whatever mode it had.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// stateWriteFile writes data atomically: a temporary file in the same directory,
// then a rename through the same descriptor.
func stateWriteFile(path string, data []byte, mode os.FileMode) error {
	rel, err := stateRel(path)
	if err != nil {
		return err
	}
	dirFD, err := stateSubdirFD(filepath.Dir(rel), true, 0o750)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	base := filepath.Base(rel)
	tmpName := "." + base + ".easy-waf.tmp"
	fd, err := openatBeneath(dirFD, tmpName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, uint64(mode.Perm()))
	if err != nil {
		return &os.PathError{Op: "create", Path: path, Err: err}
	}
	tmp := os.NewFile(uintptr(fd), tmpName)
	cleanup := func() {
		_ = tmp.Close()
		_ = unix.Unlinkat(dirFD, tmpName, 0)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return err
	}
	if err := unix.Renameat(dirFD, tmpName, dirFD, base); err != nil {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return err
	}
	return nil
}

// stateFileSize reports the size of a regular file under the state directory.
// exists is false when it is absent; a non-regular file is an error, because
// every caller is about to treat the contents as a backup.
func stateFileSize(path string) (size int64, exists bool, err error) {
	f, err := stateOpenFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	if !st.Mode().IsRegular() {
		return 0, false, fmt.Errorf("%s is not a regular file", path)
	}
	return st.Size(), true, nil
}

// stateRemoveFile deletes a file under the state directory. Unlinkat does not
// follow symlinks, so a planted link is removed rather than its target.
func stateRemoveFile(path string) error {
	rel, err := stateRel(path)
	if err != nil {
		return err
	}
	dirFD, err := stateSubdirFD(filepath.Dir(rel), false, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer unix.Close(dirFD)
	if err := unix.Unlinkat(dirFD, filepath.Base(rel), 0); err != nil && err != unix.ENOENT {
		return err
	}
	return nil
}
