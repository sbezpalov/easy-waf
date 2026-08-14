package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const (
	enrollmentFileName = "enrollment"
	enrollmentBytes    = 32
)

// FilePath is the root-readable, 0600 plaintext secret path.
func FilePath(stateDir string) string {
	return filepath.Join(stateDir, "secrets", enrollmentFileName)
}

// GenerateSecret returns a 32-byte CSPRNG secret as lowercase hex (64 chars).
func GenerateSecret() (string, error) {
	b := make([]byte, enrollmentBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashSecret returns SHA-256 hex of the secret (never log the input).
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SecretEqual is a constant-time compare of a presented secret against a stored hash.
func SecretEqual(got, wantHash string) bool {
	gotHash := HashSecret(got)
	a := []byte(gotHash)
	b := []byte(wantHash)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// WriteFile writes the plaintext secret at 0600. It never logs the secret.
func WriteFile(stateDir, secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("empty enrollment secret")
	}
	dir := filepath.Join(stateDir, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := FilePath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// RemoveFile deletes the plaintext secret after successful enrollment.
func RemoveFile(stateDir string) error {
	path := FilePath(stateDir)
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// ReadFile returns the secret for local console delivery. Callers must not log it.
func ReadFile(stateDir string) (string, error) {
	path := FilePath(stateDir)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := string(b)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", fmt.Errorf("enrollment file is empty")
	}
	return s, nil
}
