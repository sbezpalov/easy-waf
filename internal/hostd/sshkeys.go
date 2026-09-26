// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// groupFilePath is the account database consulted for privileged group membership
// (overridden in tests).
var groupFilePath = "/etc/group"

// privilegedGroups give root, or this appliance's secrets, to their members:
// sudo/admin/wheel run sudo; docker, lxd, incus-admin and libvirt start a
// container or VM with the host filesystem mounted; disk reads raw block
// devices; easy-waf reads the state directory (TLS private keys included) and
// haproxy reaches HAProxy's admin socket. Handing out SSH access to any of them
// is handing out that power.
var privilegedGroups = map[string]struct{}{
	"root":        {},
	"sudo":        {},
	"admin":       {},
	"wheel":       {},
	"docker":      {},
	"lxd":         {},
	"incus-admin": {},
	"libvirt":     {},
	"disk":        {},
	"easy-waf":    {},
	"haproxy":     {},
}

// allowPrivilegedSSHTargets reports whether the operator explicitly allowed key
// management for root-equivalent accounts.
//
// This is deliberately read from the broker's own environment (set in the
// easy-waf-hostd systemd unit, which only root can edit) rather than from the
// request: the threat model here is a compromised easy-waf-api, so any switch the
// API itself could flip would be worthless.
func allowPrivilegedSSHTargets() bool {
	return os.Getenv("EASY_WAF_HOSTD_ALLOW_PRIVILEGED_SSH_TARGETS") == "1"
}

// accountPrivilegedGroup returns the first root-equivalent group the account
// belongs to (primary GID or member list), or "" when it has none.
// A group file that cannot be read is an error: this check fails closed.
func accountPrivilegedGroup(username, primaryGID string) (string, error) {
	f, err := os.Open(groupFilePath)
	if err != nil {
		return "", fmt.Errorf("read group file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:gid:member1,member2
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		if _, ok := privilegedGroups[name]; !ok {
			continue
		}
		if primaryGID != "" && parts[2] == primaryGID {
			return name, nil
		}
		if len(parts) >= 4 {
			for _, m := range strings.Split(parts[3], ",") {
				if strings.TrimSpace(m) == username {
					return name, nil
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read group file: %w", err)
	}
	return "", nil
}

// readAuthorizedKeysPayload reads and re-validates the staged key material.
func readAuthorizedKeysPayload(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, hostspec.MaxAuthorizedKeysBytes+1))
	if err != nil {
		return nil, err
	}
	return hostspec.ValidateAuthorizedKeysContent(raw)
}

// sshAuthorizedKeys replaces authorized_keys for a managed account.
//
// Everything here runs as root on content that arrived from easy-waf-api, so the
// broker re-validates the payload itself, refuses root-equivalent target accounts
// unless the operator opted in, and writes without ever following a symlink
// (see writeAuthorizedKeys).
func sshAuthorizedKeys(username, staged string) Response {
	u, err := lookupManagedUser(username)
	if err != nil {
		return failResp("user not found", 1)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return failResp("invalid uid", 1)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return failResp("invalid gid", 1)
	}

	if !allowPrivilegedSSHTargets() {
		why, perr := privilegedAccountReason(u.Username, u.Gid)
		if perr != nil {
			return failResp("ssh-authorized-keys: "+perr.Error(), 1)
		}
		if why != "" {
			return failResp(
				"ssh-authorized-keys: refusing privileged account ("+why+
					"); set EASY_WAF_HOSTD_ALLOW_PRIVILEGED_SSH_TARGETS=1 in the easy-waf-hostd unit to allow", 1)
		}
	}

	content, err := readAuthorizedKeysPayload(staged)
	if err != nil {
		return failResp("ssh-authorized-keys: "+err.Error(), 1)
	}

	if err := writeAuthorizedKeys(u.HomeDir, uid, gid, content); err != nil {
		return failResp("ssh-authorized-keys: "+err.Error(), 1)
	}
	return okResp(nil, nil, 0)
}

// checkHomeDirNotSymlink rejects a home directory that is a symlink or not a
// directory at all, before any privileged write happens beneath it.
func checkHomeDirNotSymlink(home string) error {
	fi, err := os.Lstat(home)
	if err != nil {
		return fmt.Errorf("home: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("home is a symlink")
	}
	if !fi.IsDir() {
		return fmt.Errorf("home is not a directory")
	}
	return nil
}
