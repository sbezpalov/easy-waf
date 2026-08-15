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

// legacyToken is the parsed EASY_WAF_ADMIN_TOKEN: only its digest is kept, so
// comparisons run over a fixed 32-byte value.
type legacyToken struct {
	digest  [32]byte
	enabled bool
}

// loadLegacyToken reads EASY_WAF_ADMIN_TOKEN and refuses a token that is too
// short to resist guessing. A rejected token is treated as unset (fail closed)
// and logged once at startup.
func loadLegacyToken() legacyToken {
	tok := strings.TrimSpace(os.Getenv("EASY_WAF_ADMIN_TOKEN"))
	if tok == "" {
		return legacyToken{}
	}
	if len(tok) < MinLegacyTokenLen {
		log.Printf("[easy-waf] EASY_WAF_ADMIN_TOKEN ignored: %d characters, minimum is %d — "+
			"rotate it with `easy-waf-admin reset-appliance -bootstrap-credentials` or use a session JWT",
			len(tok), MinLegacyTokenLen)
		return legacyToken{}
	}
	return legacyToken{digest: sha256.Sum256([]byte(tok)), enabled: true}
}

// matches compares a presented bearer value in constant time.
//
// Both sides are hashed first: comparing the raw strings required a length check
// (len(raw) == len(token)) before the constant-time compare, which leaked the
// token's length to anyone probing the API.
func (t legacyToken) matches(raw string) bool {
	if !t.enabled {
		return false
	}
	got := sha256.Sum256([]byte(raw))
	return subtle.ConstantTimeCompare(got[:], t.digest[:]) == 1
}
