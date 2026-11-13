// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ValidateRevisionLabel rejects text PostgreSQL cannot store before an edge
// change can be applied. Empty and ordinary free-form Unicode labels are valid.
func ValidateRevisionLabel(label string) error {
	if !utf8.ValidString(label) || strings.ContainsRune(label, '\x00') {
		return errors.New("label must be valid UTF-8 without NUL characters")
	}
	return nil
}
