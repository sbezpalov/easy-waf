// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestValidateRevisionLabel(t *testing.T) {
	for _, label := range []string{"", "manual", "ACME renewal", "Backend — новая ревизия", "operator\nnote"} {
		if err := ValidateRevisionLabel(label); err != nil {
			t.Fatalf("valid label %q rejected: %v", label, err)
		}
	}
	for _, label := range []string{"\x00", "before\x00after", "end\x00", "invalid\xff", "\xed\xa0\x80"} {
		if err := ValidateRevisionLabel(label); err == nil {
			t.Fatalf("unsupported PostgreSQL text %q accepted", label)
		}
	}
}
