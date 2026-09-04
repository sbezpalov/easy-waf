// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
)

func TestMergeApplicationSecurityJSON(t *testing.T) {
	base := DefaultApplicationSecurity()
	out, err := MergeApplicationSecurityJSON(base, []byte(`{"basic_waf_enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.BasicWAFEnabled {
		t.Fatal("expected basic_waf false")
	}
	if !out.RateLimitEnabled {
		t.Fatal("expected rate limit preserved")
	}
}
