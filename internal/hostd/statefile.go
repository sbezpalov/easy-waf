// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// Symlink-safe access to the appliance state directory.
//
// /var/lib/easy-waf is chowned to the unprivileged easy-waf account (see
// create_user_and_layout in scripts/install.sh and packaging/deb/postinst),
// because easy-waf-api has to write generated configuration, certificates and
// revisions there. The broker runs as root and reads and writes files in the
// same tree — the rollback backups, the apt action log, staged files.
//
// That combination is a privilege-escalation primitive as soon as the broker
// resolves a path the normal way: whoever controls easy-waf-api (and the threat
// model says to assume somebody does) can replace any directory or file under
// the state directory with a symlink, and root will follow it. Reading through
// one turns into "copy /etc/shadow somewhere world-readable"; creating through
// one turns into "truncate any root-owned file".
//
// Everything the broker touches in this tree therefore goes through the helpers
// below, which anchor at the state directory itself — the one component the
// easy-waf account cannot replace, because /var/lib is root-owned — and refuse
// to traverse a symlink from there down. Same technique already used for
// authorized_keys in sshkeys_linux.go.
//
// The platform-specific halves are in statefile_linux.go (openat2 with
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) and statefile_other.go (a weaker
// O_NOFOLLOW-based approximation for development builds).

// stateDir is the anchor. Only its contents are attacker-controlled; the
// directory entry itself lives in root-owned /var/lib. A variable rather than a
// constant so the tests can point it at a temporary tree — nothing outside the
// tests ever assigns to it.
var stateDir = "/var/lib/easy-waf"

// stateRel converts an absolute path under the state directory into the
// relative form the helpers take, rejecting anything outside it. Callers keep
// using absolute paths so the constants and log messages stay readable.
func stateRel(path string) (string, error) {
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(stateDir, clean)
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
	return stateRel(path)
}
