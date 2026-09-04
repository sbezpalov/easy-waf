// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
)

func TestRandomAlphanumericPassword_lengthAndAlphabet(t *testing.T) {
	s, err := RandomAlphanumericPassword(19)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 19 {
		t.Fatalf("len=%d", len(s))
	}
	for _, r := range s {
		if !strings.ContainsRune(PasswordAlphabet, r) {
			t.Fatalf("unexpected rune %q in %q", r, s)
		}
	}
}

func TestParseAndBuildPostgresURL_roundTrip(t *testing.T) {
	raw := "postgres://easywaf:oldpass@127.0.0.1:5432/easywaf?sslmode=disable"
	parts, err := ParsePostgresURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parts.User != "easywaf" || parts.Host != "127.0.0.1" || parts.Port != "5432" || parts.DBName != "easywaf" || parts.SSLMode != "disable" {
		t.Fatalf("%+v", parts)
	}
	out := BuildPostgresURL(parts.User, "newpass", parts)
	p2, err := ParsePostgresURL(out)
	if err != nil {
		t.Fatal(err)
	}
	if p2.User != "easywaf" {
		t.Fatalf("%+v", p2)
	}
}
