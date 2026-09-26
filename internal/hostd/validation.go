// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

const maxStagedFileBytes int64 = 16 << 20

// materializeStagedFile copies an untrusted staging file into a root-owned
// runtime file. On Linux, openStagedFile uses openat2 beneath the staging root,
// closing symlink and path-swap races before privileged consumers use it.
func materializeStagedFile(path string) (string, func(), error) {
	src, err := openStagedFile(path)
	if err != nil {
		return "", func() {}, err
	}
	defer src.Close()
	if err := os.MkdirAll("/run/easy-waf", 0o750); err != nil {
		return "", func() {}, err
	}
	dst, err := os.CreateTemp("/run/easy-waf", "staged-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(dst.Name()) }
	ok := false
	defer func() {
		_ = dst.Close()
		if !ok {
			cleanup()
		}
	}()
	if err := dst.Chmod(0o600); err != nil {
		return "", func() {}, err
	}
	written, err := io.Copy(dst, io.LimitReader(src, maxStagedFileBytes+1))
	if err != nil {
		return "", func() {}, err
	}
	if written > maxStagedFileBytes {
		return "", func() {}, fmt.Errorf("staged file exceeds %d bytes", maxStagedFileBytes)
	}
	if err := dst.Sync(); err != nil {
		return "", func() {}, err
	}
	if err := dst.Close(); err != nil {
		return "", func() {}, err
	}
	ok = true
	return dst.Name(), cleanup, nil
}

func lookupManagedUser(username string) (*user.User, error) {
	if !hostspec.ManageableUsername(username) {
		return nil, fmt.Errorf("user is protected or invalid")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid < 1000 {
		return nil, fmt.Errorf("system account is protected")
	}
	home := filepath.Clean(u.HomeDir)
	if home == "/" || !strings.HasPrefix(home, "/home/") {
		return nil, fmt.Errorf("user home is outside /home")
	}
	return u, nil
}

// validateNftFile checks a ruleset before nft, running as root, reads it.
func validateNftFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return hostspec.ValidateNftRuleset(b)
}
