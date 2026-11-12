// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// Symlink-safe access to the root-owned broker state directory. Rollback
// backups and apt bookkeeping live here rather than in the easy-waf-owned
// application state, so a compromised API cannot replace otherwise regular
// files or directories between broker operations. The no-follow helpers remain
// defense in depth against accidental unsafe links and future ownership drift.
//
// The platform-specific halves are in statefile_linux.go (openat2 with
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) and statefile_other.go (a weaker
// O_NOFOLLOW-based approximation for development builds).

// stateDir is created by easy-waf-hostd.service with root ownership and mode
// 0700. A variable rather than a constant lets tests point it at a temporary tree.
var stateDir = "/var/lib/easy-waf-hostd"

// untrustedStateDir remains the application-owned tree. Only staged inputs are
// read from it, through a separate descriptor anchored at this directory.
var untrustedStateDir = "/var/lib/easy-waf"

// stateRel converts an absolute path under the state directory into the
// relative form the helpers take, rejecting anything outside it. Callers keep
// using absolute paths so the constants and log messages stay readable.
func stateRel(path string) (string, error) {
	return relToStateRoot(stateDir, path)
}

func relToStateRoot(root, path string) (string, error) {
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(root, clean)
	if err != nil {
		return "", fmt.Errorf("path is outside the state directory")
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path is outside the state directory")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path is outside the state directory")
	}
	return rel, nil
}

// stateStagingRel is stateRel for a staged file, with the staging-path
// validation the broker already applies applied first.
func stateStagingRel(path string) (string, error) {
	if !hostspec.ValidStagedPath(path) {
		return "", fmt.Errorf("invalid staged path")
	}
	return relToStateRoot(untrustedStateDir, path)
}
