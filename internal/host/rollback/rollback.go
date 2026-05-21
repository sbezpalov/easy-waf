package rollback

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	DefaultSeconds = 90
	MinSeconds     = 30
	MaxSeconds     = 600
)

// GenerateToken returns a hex token suitable for rollback unit names (8–64 hex chars).
func GenerateToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rollback token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ClampRollbackSeconds enforces [30, 600]; zero or negative uses DefaultSeconds (90).
func ClampRollbackSeconds(sec int) int {
	if sec <= 0 {
		return DefaultSeconds
	}
	if sec < MinSeconds {
		return MinSeconds
	}
	if sec > MaxSeconds {
		return MaxSeconds
	}
	return sec
}

// ValidToken reports whether token matches privileged helper expectations.
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
