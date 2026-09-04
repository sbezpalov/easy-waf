// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package rollback

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

const (
	DefaultSeconds = hostspec.RollbackDefaultSec
	MinSeconds     = hostspec.RollbackMinSec
	MaxSeconds     = hostspec.RollbackMaxSec
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
	return hostspec.ClampRollback(sec)
}

// ValidToken reports whether token matches rollback naming rules.
func ValidToken(token string) bool {
	return hostspec.ValidToken(token)
}
