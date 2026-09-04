// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Non-Linux fallback. openat2 with RESOLVE_NO_SYMLINKS has no portable
// equivalent, so this approximates it: every directory component is checked with
// Lstat before use, and the file itself is opened with O_NOFOLLOW.
//
// That leaves a race a determined local attacker could win by swapping a
// component between the check and the open. It is accepted here because the
// broker only ships on Linux — these builds exist so the package compiles and
// its tests run on a developer's machine. The production path is
// statefile_linux.go, which is race-free.

func stateResolveDir(relDir string, create bool, mode os.FileMode) (string, error) {
	dir := stateDir
	if fi, err := os.Lstat(dir); err != nil {
		return "", err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink", dir)
	}
	for _, part := range splitClean(relDir) {
		dir = filepath.Join(dir, part)
		if create {
			if err := os.Mkdir(dir, mode.Perm()); err != nil && !os.IsExist(err) {
				return "", err
			}
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s is a symlink", dir)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("%s is not a directory", dir)
		}
	}
	return dir, nil
}

func splitClean(relDir string) []string {
	parts := []string{}
	cleaned := filepath.Clean(relDir)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return parts
	}
	cur := cleaned
	for cur != "." && cur != string(filepath.Separator) {
		parts = append([]string{filepath.Base(cur)}, parts...)
		cur = filepath.Dir(cur)
	}
	return parts
}

func stateOpenFile(path string) (*os.File, error) {
	rel, err := stateRel(path)
	if err != nil {
		return nil, err
	}
	dir, err := stateResolveDir(filepath.Dir(rel), false, 0)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, filepath.Base(rel)),
		os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func stateCreateFile(path string, mode os.FileMode) (*os.File, error) {
	rel, err := stateRel(path)
	if err != nil {
		return nil, err
	}
	dir, err := stateResolveDir(filepath.Dir(rel), true, 0o750)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, filepath.Base(rel)),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode.Perm())
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func stateWriteFile(path string, data []byte, mode os.FileMode) error {
	rel, err := stateRel(path)
	if err != nil {
		return err
	}
	dir, err := stateResolveDir(filepath.Dir(rel), true, 0o750)
	if err != nil {
		return err
	}
	base := filepath.Base(rel)
	tmpPath := filepath.Join(dir, "."+base+".easy-waf.tmp")
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode.Perm())
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
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
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, base)); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

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

func stateRemoveFile(path string) error {
	rel, err := stateRel(path)
	if err != nil {
		return err
	}
	dir, err := stateResolveDir(filepath.Dir(rel), false, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Remove(filepath.Join(dir, filepath.Base(rel))); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
