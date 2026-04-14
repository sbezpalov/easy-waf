package auth

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// LoadJWTSecret reads EASY_WAF_JWT_SECRET or a persistent file under stateDir/secrets/jwt.secret.
func LoadJWTSecret(stateDir string) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("EASY_WAF_JWT_SECRET")); v != "" {
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
