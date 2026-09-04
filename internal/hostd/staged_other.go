// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hostd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// See staged_linux.go for why the staging directory itself cannot be trusted as
// an anchor: it belongs to the unprivileged easy-waf account. EvalSymlinks below
// resolves the whole path, so a symlinked staging directory would resolve
// outside and be rejected — this Lstat only makes the refusal explicit.
func openStagedFile(path string) (*os.File, error) {
	if !hostspec.ValidStagedPath(path) {
		return nil, fmt.Errorf("invalid staged path")
	}
	if fi, err := os.Lstat(filepath.Clean(hostspec.StagingDirPrefix)); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("staging directory is a symlink")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("staged path is not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !hostspec.ValidStagedPath(resolved) {
		return nil, fmt.Errorf("staged file resolves outside staging")
	}
	return os.Open(resolved)
}
