package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MinJWTSecretLen is the shortest EASY_WAF_JWT_SECRET that will be accepted.
//
// Every other shared secret here has a floor and fails closed — the legacy admin
// token at 24, the metrics token at 16. The JWT signing key had none, which was
// the wrong way round: it is the one secret that yields full management access,
// and guessing it forges a session with no password check, no rate limit and no
// failed-login audit record. SignJWT already refused to sign below 16 bytes
// while ParseJWT verified anything, so a short operator-set value produced an
// appliance nobody could log into but anybody who guessed it could forge tokens
// for.
const MinJWTSecretLen = 32

// LoadJWTSecret reads EASY_WAF_JWT_SECRET or a persistent file under stateDir/secrets/jwt.secret.
func LoadJWTSecret(stateDir string) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("EASY_WAF_JWT_SECRET")); v != "" {
		if len(v) < MinJWTSecretLen {
			return nil, fmt.Errorf("EASY_WAF_JWT_SECRET is %d characters; at least %d are required "+
				"(unset it to have a 32-byte random key generated in %s)",
				len(v), MinJWTSecretLen, filepath.Join(stateDir, "secrets", "jwt.secret"))
		}
		return []byte(v), nil
	}
	p := filepath.Join(stateDir, "secrets", "jwt.secret")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return []byte(strings.TrimSpace(string(b))), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(enc+"\n"), 0o600); err != nil {
		return nil, err
	}
	return []byte(enc), nil
}
