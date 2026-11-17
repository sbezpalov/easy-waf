// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func TestPostgresSuperuserSQLCommandReadsSQLFromStdin(t *testing.T) {
	const sql = "ALTER USER fixture WITH PASSWORD 'fixture-password';"
	cmd := postgresSuperuserSQLCommand(sql)
	want := []string{"runuser", "-u", "postgres", "--", "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-f", "-"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatal("unexpected PostgreSQL client arguments")
	}
	input, err := io.ReadAll(cmd.Stdin)
	if err != nil || string(input) != sql+"\n" {
		t.Fatal("PostgreSQL client did not receive the SQL statement on stdin")
	}
}

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

func TestParsePostgresURLReportsMalformedInputWithoutCredentials(t *testing.T) {
	const dsn = "postgres://fixture:fixture-password%zz@localhost/easywaf"
	_, err := ParsePostgresURL(dsn)
	if err == nil || err.Error() != "invalid PostgreSQL URL syntax" {
		t.Fatal("expected a fixed diagnostic for malformed PostgreSQL URLs")
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
