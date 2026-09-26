// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"
)

func TestSplitSQLStatements_basics(t *testing.T) {
	got := splitSQLStatements("CREATE TABLE a (id int);\n\nALTER TABLE a ADD COLUMN b int;\n")
	want := []string{"CREATE TABLE a (id int)", "ALTER TABLE a ADD COLUMN b int"}
	assertStatements(t, got, want)
}

func TestSplitSQLStatements_trailingStatementWithoutSemicolon(t *testing.T) {
	got := splitSQLStatements("SELECT 1;\nSELECT 2")
	assertStatements(t, got, []string{"SELECT 1", "SELECT 2"})
}

func TestSplitSQLStatements_dropsComments(t *testing.T) {
	in := `-- leading comment
CREATE TABLE a (id int); -- trailing note
/* block
   comment */
ALTER TABLE a ADD COLUMN b int;
-- only a comment, no statement
`
	got := splitSQLStatements(in)
	if len(got) != 2 {
		t.Fatalf("got %d statements: %q", len(got), got)
	}
	for _, s := range got {
		if strings.Contains(s, "comment") || strings.Contains(s, "note") {
			t.Fatalf("comment leaked into statement: %q", s)
		}
	}
}

// PostgreSQL allows nested block comments; a naive scanner ends the comment at
// the first */ and then executes the rest as SQL.
func TestSplitSQLStatements_nestedBlockComments(t *testing.T) {
	got := splitSQLStatements("/* outer /* inner */ still comment; */ SELECT 1;")
	assertStatements(t, got, []string{"SELECT 1"})
}

// The reason this scanner exists: a semicolon inside a dollar-quoted block is
// not a statement separator.
func TestSplitSQLStatements_dollarQuotedBlock(t *testing.T) {
	in := `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'mood') THEN
        CREATE TYPE mood AS ENUM ('ok', 'bad');
    END IF;
END $$;
SELECT 1;`
	got := splitSQLStatements(in)
	if len(got) != 2 {
		t.Fatalf("dollar-quoted block was split into %d statements: %q", len(got), got)
	}
	if !strings.Contains(got[0], "END IF;") || !strings.HasSuffix(got[0], "END $$") {
		t.Fatalf("dollar-quoted body was mangled: %q", got[0])
	}
}

func TestSplitSQLStatements_taggedDollarQuote(t *testing.T) {
	in := `CREATE FUNCTION f() RETURNS int AS $body$
BEGIN
    RETURN 1; -- inner
END;
$body$ LANGUAGE plpgsql;
SELECT 2;`
	got := splitSQLStatements(in)
	if len(got) != 2 {
		t.Fatalf("tagged dollar quote split into %d statements: %q", len(got), got)
	}
	if !strings.Contains(got[0], "RETURN 1; -- inner") {
		t.Fatalf("function body was rewritten: %q", got[0])
	}
}

func TestSplitSQLStatements_semicolonInsideLiterals(t *testing.T) {
	got := splitSQLStatements(`INSERT INTO t (v) VALUES ('a;b');
INSERT INTO t (v) VALUES ('it''s; fine');
ALTER TABLE "weird;name" ADD COLUMN c int;`)
	if len(got) != 3 {
		t.Fatalf("got %d statements: %q", len(got), got)
	}
	if !strings.Contains(got[0], "'a;b'") {
		t.Fatalf("literal was split: %q", got[0])
	}
	if !strings.Contains(got[1], "'it''s; fine'") {
		t.Fatalf("escaped quote mishandled: %q", got[1])
	}
	if !strings.Contains(got[2], `"weird;name"`) {
		t.Fatalf("quoted identifier was split: %q", got[2])
	}
}

// A semicolon inside a comment must not split either.
func TestSplitSQLStatements_semicolonInComment(t *testing.T) {
	got := splitSQLStatements("SELECT 1 -- note; more\n;\nSELECT 2;")
	assertStatements(t, got, []string{"SELECT 1", "SELECT 2"})
}

func TestSplitSQLStatements_emptyInput(t *testing.T) {
	for _, in := range []string{"", "   \n\t", "-- just a comment\n", "/* only */", ";;;"} {
		if got := splitSQLStatements(in); len(got) != 0 {
			t.Fatalf("input %q produced %d statements: %q", in, len(got), got)
		}
	}
}

func TestDollarQuoteTag(t *testing.T) {
	cases := map[string]string{
		"$$body$$":      "$$",
		"$tag$x$tag$":   "$tag$",
		"$_x1$a$_x1$":   "$_x1$",
		"$1x$":          "", // a tag may not start with a digit
		"$ $":           "",
		"$":             "",
		"total$":        "",
		"$no-close":     "",
		"$has space$ x": "",
	}
	for in, want := range cases {
		got, ok := dollarQuoteTag(in)
		if want == "" {
			if ok {
				t.Fatalf("dollarQuoteTag(%q) = %q, want no tag", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("dollarQuoteTag(%q) = %q/%v, want %q", in, got, ok, want)
		}
	}
}

// The shipped migrations must keep producing exactly the statements the previous
// line-based splitter produced, so upgrading an existing appliance is a no-op.
func TestSplitSQLStatements_matchesLegacyOnShippedMigrations(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range all {
		raw := m.sql
		legacy := legacySplitForTest(raw)
		got := splitSQLStatements(raw)
		if len(got) != len(legacy) {
			t.Fatalf("migration %d: %d statements, legacy produced %d", i+1, len(got), len(legacy))
		}
		for j := range got {
			if normalizeSQL(got[j]) != normalizeSQL(legacy[j]) {
				t.Fatalf("migration %d statement %d differs:\nnew:    %s\nlegacy: %s",
					i+1, j+1, got[j], legacy[j])
			}
		}
	}
}

// legacySplitForTest reproduces the previous strip-comments-then-split behaviour.
func legacySplitForTest(raw string) []string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	var out []string
	for _, p := range strings.Split(b.String(), ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeSQL collapses whitespace so comment removal does not count as a diff.
func normalizeSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func assertStatements(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d statements %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range got {
		if normalizeSQL(got[i]) != normalizeSQL(want[i]) {
			t.Fatalf("statement %d = %q, want %q", i+1, got[i], want[i])
		}
	}
}
