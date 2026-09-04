// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"os"
	"strings"
)

// MinLegacyTokenLen is the shortest EASY_WAF_ADMIN_TOKEN the API will accept.
//
// The legacy token is a bearer credential with full API access, no expiry and no
// lockout, so it has to carry its own entropy. `easy-waf-admin
// reset-appliance -bootstrap-credentials` generates tokens well above this.
const MinLegacyTokenLen = 24

// StaticToken is a shared secret read from the environment. Only its digest is
// kept, so every comparison runs over a fixed 32-byte value.
type StaticToken struct {
	digest  [32]byte
	enabled bool
}

// LoadStaticToken reads a token from env and refuses one that is too short to
// resist guessing. A rejected or missing token is disabled (fail closed) and
// reported once at startup.
func LoadStaticToken(envName string, minLen int) StaticToken {
	tok := strings.TrimSpace(os.Getenv(envName))
	if tok == "" {
		return StaticToken{}
	}
	if len(tok) < minLen {
		log.Printf("[easy-waf] %s ignored: %d characters, minimum is %d — "+
			"rotate it with `easy-waf-admin reset-appliance -bootstrap-credentials` or use a session JWT",
			envName, len(tok), minLen)
		return StaticToken{}
	}
	return StaticToken{digest: sha256.Sum256([]byte(tok)), enabled: true}
}

// Enabled reports whether a usable token was configured.
func (t StaticToken) Enabled() bool { return t.enabled }

// Matches compares a presented bearer value in constant time.
//
// Both sides are hashed first: comparing the raw strings required a length check
// (len(raw) == len(token)) before the constant-time compare, which leaked the
// token's length to anyone probing the API.
func (t StaticToken) Matches(raw string) bool {
	if !t.enabled {
		return false
	}
	got := sha256.Sum256([]byte(raw))
	return subtle.ConstantTimeCompare(got[:], t.digest[:]) == 1
}

// loadLegacyToken reads the legacy full-access EASY_WAF_ADMIN_TOKEN.
func loadLegacyToken() StaticToken {
	return LoadStaticToken("EASY_WAF_ADMIN_TOKEN", MinLegacyTokenLen)
}
