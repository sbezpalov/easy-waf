// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package hostd

import (
	"os"
	"syscall"
)

func openFileNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}

func setPathOwner(path string, uid, gid int) error {
	return os.Lchown(path, uid, gid)
}

func setFileOwner(file *os.File, uid, gid int) error {
	return file.Chown(uid, gid)
}
