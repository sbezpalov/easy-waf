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

// writeAuthorizedKeys is the non-Linux fallback used for development builds.
// The appliance runs Linux, where the openat2 implementation in sshkeys_linux.go
// gives race-free symlink refusal; here O_NOFOLLOW plus Lstat checks cover the
// same ground well enough for a developer machine.
func writeAuthorizedKeys(home string, uid, gid int, content []byte) error {
	if err := checkHomeDirNotSymlink(home); err != nil {
		return err
	}

	sshDir := filepath.Join(home, ".ssh")
	switch fi, err := os.Lstat(sshDir); {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf(".ssh is a symlink")
		}
		if !fi.IsDir() {
			return fmt.Errorf(".ssh is not a directory")
		}
	case os.IsNotExist(err):
		if err := os.Mkdir(sshDir, 0o700); err != nil {
			return fmt.Errorf("mkdir .ssh: %w", err)
		}
	default:
		return fmt.Errorf("stat .ssh: %w", err)
	}
	// Lchown never dereferences, so a swapped .ssh cannot redirect ownership.
	if err := os.Lchown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown .ssh: %w", err)
	}

	tmpPath := filepath.Join(sshDir, ".authorized_keys.easy-waf")
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open authorized_keys tmp: %w", err)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := f.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("write authorized_keys: %w", err)
	}
	if err := f.Chown(uid, gid); err != nil {
		cleanup()
		return fmt.Errorf("chown authorized_keys: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod authorized_keys: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync authorized_keys: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close authorized_keys: %w", err)
	}
	finalPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename authorized_keys: %w", err)
	}
	return nil
}
