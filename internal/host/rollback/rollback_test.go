// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package rollback

import "testing"

func TestGenerateToken_format(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(tok))
	}
	if !ValidToken(tok) {
		t.Fatalf("invalid token %q", tok)
	}
}

func TestValidToken(t *testing.T) {
	if ValidToken("abc") {
		t.Fatal("too short")
	}
	if ValidToken("ghijklmnop") {
		t.Fatal("non-hex")
	}
	if !ValidToken("abcdef0123456789") {
		t.Fatal("valid 16-char hex")
	}
}

func TestClampRollbackSeconds(t *testing.T) {
	if ClampRollbackSeconds(0) != DefaultSeconds {
		t.Fatalf("zero -> default")
	}
	if ClampRollbackSeconds(29) != MinSeconds {
		t.Fatalf("29 -> 30")
	}
	if ClampRollbackSeconds(30) != 30 {
		t.Fatal("30")
	}
	if ClampRollbackSeconds(600) != 600 {
		t.Fatal("600")
	}
	if ClampRollbackSeconds(9999) != MaxSeconds {
		t.Fatalf("9999 -> 600")
	}
}
