// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

const (
	// MaxAuthorizedKeysBytes caps an authorized_keys payload. Real key sets are a
	// few hundred bytes per key; anything larger is a bug or an attack.
	MaxAuthorizedKeysBytes = 64 << 10
	// MaxAuthorizedKeysLines caps how many keys one account may receive.
	MaxAuthorizedKeysLines = 128
)

// sshAuthorizedKeyLine matches "<type> <base64>[ comment]" and nothing else.
//
// The anchor at the start is a security control, not cosmetics: an authorized_keys
// line may begin with an options field (command="…", environment="LD_PRELOAD=…",
// permitopen=…). Those options execute code as the account owner on every login,
// so a key line that starts with anything other than a key type is rejected.
var sshAuthorizedKeyLine = regexp.MustCompile(`^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/=]+( .*)?$`)

// ValidateSSHPublicKeys checks authorized_keys lines before writing.
func ValidateSSHPublicKeys(keys []string) error {
	if len(keys) > MaxAuthorizedKeysLines {
		return fmt.Errorf("too many ssh keys: %d (max %d)", len(keys), MaxAuthorizedKeysLines)
	}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("invalid ssh key: embedded newline")
		}
		if !sshAuthorizedKeyLine.MatchString(k) {
			return fmt.Errorf("invalid ssh key format")
		}
	}
	return nil
}

// ValidateAuthorizedKeysContent re-validates a rendered authorized_keys file and
// returns its normalized form (one validated key per line, trailing newline).
//
// easy-waf-hostd calls this on the privileged side: the API-side check in
// internal/host/users is advisory, because a compromised easy-waf-api can talk to
// the broker directly. Writing unvalidated bytes into a sudoer's authorized_keys
// would turn control of easy-waf-api into root on the appliance.
func ValidateAuthorizedKeysContent(b []byte) ([]byte, error) {
	if len(b) > MaxAuthorizedKeysBytes {
		return nil, fmt.Errorf("authorized_keys exceeds %d bytes", MaxAuthorizedKeysBytes)
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, fmt.Errorf("authorized_keys: NUL byte")
	}

	lines := strings.Split(string(b), "\n")
	keys := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r"))
		if ln == "" {
			continue
		}
		keys = append(keys, ln)
	}
	if err := ValidateSSHPublicKeys(keys); err != nil {
		return nil, err
	}

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('\n')
	}
	return []byte(sb.String()), nil
}
