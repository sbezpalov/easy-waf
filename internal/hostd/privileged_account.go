// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Overridden in tests.
var (
	sudoersPath    = "/etc/sudoers"
	sudoersDirPath = "/etc/sudoers.d"
)

// privilegedAccountReason explains why an account is root-equivalent, or
// returns "" when it is not. It checks group membership and sudoers rules
// that name the user or one of its groups directly. Anything it cannot verify
// counts as privileged: the caller is a possibly compromised easy-waf-api.
func privilegedAccountReason(username, primaryGID string) (string, error) {
	grp, err := accountPrivilegedGroup(username, primaryGID)
	if err != nil {
		return "", err
	}
	if grp != "" {
		return "member of privileged group " + grp, nil
	}
	member, local, err := accountGroups(username, primaryGID)
	if err != nil {
		return "", err
	}
	return sudoersGrant(username, member, local)
}

// accountGroups reads groupFilePath and returns the groups the account belongs
// to (by primary GID or member list) and every group defined there.
func accountGroups(username, primaryGID string) (member, local map[string]struct{}, err error) {
	f, err := os.Open(groupFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read group file: %w", err)
	}
	defer f.Close()
	member = map[string]struct{}{}
	local = map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) < 3 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		local[parts[0]] = struct{}{}
		in := primaryGID != "" && parts[2] == primaryGID
		if !in && len(parts) >= 4 {
			for _, m := range strings.Split(parts[3], ",") {
				if strings.TrimSpace(m) == username {
					in = true
					break
				}
			}
		}
		if in {
			member[parts[0]] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("read group file: %w", err)
	}
	return member, local, nil
}

// sudoersGrant scans /etc/sudoers and /etc/sudoers.d for a rule or alias that
// names the user, ALL, or a group the user is in. A %group that is not in the
// local group file (LDAP/SSSD) cannot be checked and counts as a grant.
//
// The scan is deliberately coarse: any token on a non-Defaults line counts, so
// it can refuse an account sudo would not actually empower, never the reverse.
func sudoersGrant(username string, member, local map[string]struct{}) (string, error) {
	files := []string{sudoersPath}
	entries, err := os.ReadDir(sudoersDirPath)
	switch {
	case err == nil:
		for _, e := range entries {
			name := e.Name()
			// sudo ignores names with a dot or ending in ~.
			if e.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
				continue
			}
			files = append(files, filepath.Join(sudoersDirPath, name))
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", fmt.Errorf("read %s: %w", sudoersDirPath, err)
	}

	for _, path := range files {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "Defaults") {
				continue
			}
			if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#include") {
				continue
			}
			if strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "@include") {
				// Only the stock includedir is followed; anything else is unknown.
				if f := strings.Fields(line); len(f) == 2 && (f[0] == "#includedir" || f[0] == "@includedir") && filepath.Clean(f[1]) == sudoersDirPath {
					continue
				}
				return "sudoers includes " + line + ", which easy-waf-hostd does not follow", nil
			}
			// A rule whose user list is ALL applies to every account.
			if users := strings.Fields(line)[0]; users == "ALL" || strings.HasPrefix(users, "ALL,") || strings.Contains(users, ",ALL") {
				return "a sudo rule in " + path + " applies to ALL users", nil
			}
			for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
				return r == ' ' || r == '\t' || r == ',' || r == '=' || r == '(' || r == ')' || r == ':'
			}) {
				switch {
				case tok == username:
					return "named in " + path, nil
				case strings.HasPrefix(tok, "%"):
					g := strings.TrimPrefix(strings.TrimPrefix(tok, "%:"), "%")
					if _, in := member[g]; in {
						return "group " + g + " has a sudo rule in " + path, nil
					}
					// privilegedGroups membership is checked already; stock
					// Ubuntu sudoers names %admin, which no longer exists.
					if _, handled := privilegedGroups[g]; handled {
						continue
					}
					if _, known := local[g]; !known {
						return "sudo rule for group " + g + " in " + path + " cannot be checked (not in /etc/group)", nil
					}
				}
			}
		}
	}
	return "", nil
}
