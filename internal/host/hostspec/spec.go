// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package hostspec holds shared validation for host management (API + easy-waf-hostd).
package hostspec

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/systemdallow"
)

const (
	StagingDirPrefix   = "/var/lib/easy-waf/staging/"
	RollbackDefaultSec = 90
	RollbackMinSec     = 30
	RollbackMaxSec     = 600
)

var (
	usernameRE     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	journalSinceRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2}(:[0-9]{2})?)?$|^[0-9]+[smhdw]?$`)
	// verbose/export can dump binary fields and broader metadata; keep
	// operator-facing formats only.
	journalOutput = map[string]struct{}{
		"short": {}, "short-iso": {}, "short-precise": {}, "short-iso-precise": {},
		"json": {}, "json-pretty": {}, "json-sse": {}, "json-seq": {}, "cat": {},
	}
	// Matches journal.BlockedLines; interactive API queries still clamp to 2000.
	journalMaxLines = 5000


	jailNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

	journalPriority = map[string]struct{}{
		"0": {}, "1": {}, "2": {}, "3": {}, "4": {}, "5": {}, "6": {}, "7": {},
		"emerg": {}, "alert": {}, "crit": {}, "err": {}, "warning": {}, "notice": {}, "info": {}, "debug": {},
	}
)

// ValidToken reports whether token matches rollback unit naming (hex, 8–64 chars).
func ValidToken(token string) bool {
	if len(token) < 8 || len(token) > 64 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// ClampRollback enforces [30, 600]; zero or negative uses RollbackDefaultSec.
func ClampRollback(sec int) int {
	if sec <= 0 {
		return RollbackDefaultSec
	}
	if sec < RollbackMinSec {
		return RollbackMinSec
	}
	if sec > RollbackMaxSec {
		return RollbackMaxSec
	}
	return sec
}

// ValidJailName checks fail2ban jail name syntax.
func ValidJailName(jail string) bool {
	jail = strings.TrimSpace(jail)
	return jail != "" && jailNameRE.MatchString(jail)
}

// ValidIP reports whether s is a parseable IP address.
func ValidIP(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}

// ValidUsername checks local account name syntax.
func ValidUsername(name string) bool {
	return usernameRE.MatchString(name)
}

// ManageableUsername rejects protected accounts for privileged user operations.
func ManageableUsername(name string) bool {
	if !ValidUsername(name) {
		return false
	}
	return name != "root" && name != "easy-waf"
}

// DeletableUsername is kept as the API-specific name for account deletion.
func DeletableUsername(name string) bool { return ManageableUsername(name) }

// ValidStagedPath accepts only files under /var/lib/easy-waf/staging/.
func ValidStagedPath(path string) bool {
	clean := filepath.Clean(path)
	prefix := filepath.Clean(StagingDirPrefix)
	rel, err := filepath.Rel(prefix, clean)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ValidRollbackTimeout is a decimal seconds string in [30, 600].
func ValidRollbackTimeout(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	return n >= RollbackMinSec && n <= RollbackMaxSec
}

// JournalGrepBlocked selects HAProxy httplog lines the edge refused: PR-- is an
// http-request deny, LR-- a local response such as http-request return.
const JournalGrepBlocked = "[PL]R--"

// journalGrep is the only set of --grep patterns accepted: the value is a regex.
var journalGrep = map[string]struct{}{JournalGrepBlocked: {}}

// ValidateJournalArgs validates journalctl arguments (not including the "journal" opcode).
// At least one allowlisted -u is required so a peer cannot dump the whole system journal.
func ValidateJournalArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("journal: empty args")
	}
	units := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.ContainsAny(a, "'\";&|$()") {
			return fmt.Errorf("journal: invalid arg")
		}
		switch a {
		case "--no-pager":
			continue
		case "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: -n requires value")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 || n > journalMaxLines {
				return fmt.Errorf("journal: invalid -n")
			}
			i++
		case "-u":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: -u requires unit")
			}
			u := args[i+1]
			if !strings.HasSuffix(u, ".service") {
				u += ".service"
			}
			if !systemdallow.AllowedUnit(u) {
				return fmt.Errorf("journal: unit not allowed")
			}
			units++
			i++
		case "--since", "--until":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: %s requires value", a)
			}
			if !journalSinceRE.MatchString(args[i+1]) {
				return fmt.Errorf("journal: invalid %s", a)
			}
			i++
		case "-p":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: -p requires value")
			}
			if _, ok := journalPriority[strings.ToLower(args[i+1])]; !ok {
				return fmt.Errorf("journal: invalid priority")
			}
			i++
		case "--grep":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: --grep requires value")
			}
			if _, ok := journalGrep[args[i+1]]; !ok {
				return fmt.Errorf("journal: grep pattern not allowed")
			}
			i++
		case "--output":
			if i+1 >= len(args) {
				return fmt.Errorf("journal: --output requires value")
			}
			if _, ok := journalOutput[args[i+1]]; !ok {
				return fmt.Errorf("journal: invalid output")
			}
			i++
		default:
			return fmt.Errorf("journal: flag not allowed: %s", a)
		}
	}
	if units < 1 {
		return fmt.Errorf("journal: -u required")
	}
	return nil
}
