// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import "strings"

// splitSQLStatements splits a migration file into individual statements.
//
// A plain strings.Split(sql, ";") — what this replaced — breaks on any semicolon
// that is not a statement separator. That is fine for the migrations shipped so
// far, and wrong for the first one that needs a dollar-quoted block:
//
//	DO $$ BEGIN
//	    IF NOT EXISTS (...) THEN ALTER TABLE t ADD COLUMN c int; END IF;
//	END $$;
//
// which would be executed as three broken fragments. The same applies to a
// semicolon inside a string literal or a comment. This scanner tracks the
// contexts PostgreSQL recognises and only splits at top level.
//
// Comments are dropped: PostgreSQL does not need them, and removing them keeps
// "statement is empty" easy to detect.
func splitSQLStatements(sql string) []string {
	var (
		out  []string
		cur  strings.Builder
		i    int
		n    = len(sql)
		bloc int // depth of /* */ (PostgreSQL nests them)
	)

	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}

	for i < n {
		c := sql[i]

		// Inside a block comment: consume until the matching close.
		if bloc > 0 {
			switch {
			case strings.HasPrefix(sql[i:], "/*"):
				bloc++
				i += 2
			case strings.HasPrefix(sql[i:], "*/"):
				bloc--
				i += 2
				if bloc == 0 {
					cur.WriteByte(' ')
				}
			default:
				i++
			}
			continue
		}

		switch {
		case strings.HasPrefix(sql[i:], "--"):
			for i < n && sql[i] != '\n' {
				i++
			}
			cur.WriteByte(' ')

		case strings.HasPrefix(sql[i:], "/*"):
			bloc = 1
			i += 2

		case c == '\'', c == '"':
			// String literal or quoted identifier: a doubled quote is an escape.
			q := c
			cur.WriteByte(q)
			i++
			for i < n {
				if sql[i] == q {
					if i+1 < n && sql[i+1] == q {
						cur.WriteByte(q)
						cur.WriteByte(q)
						i += 2
						continue
					}
					cur.WriteByte(q)
					i++
					break
				}
				cur.WriteByte(sql[i])
				i++
			}

		case c == '$':
			if tag, ok := dollarQuoteTag(sql[i:]); ok {
				end := strings.Index(sql[i+len(tag):], tag)
				if end < 0 {
					// Unterminated: emit the remainder unchanged and let
					// PostgreSQL report the syntax error rather than guessing.
					cur.WriteString(sql[i:])
					i = n
					break
				}
				stop := i + len(tag) + end + len(tag)
				cur.WriteString(sql[i:stop])
				i = stop
			} else {
				cur.WriteByte(c)
				i++
			}

		case c == ';':
			flush()
			i++

		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return out
}

// dollarQuoteTag reports the dollar-quote delimiter at the start of s ("$$" or
// "$tag$"), if any. Tags follow identifier rules: letters, digits and
// underscores, not starting with a digit.
func dollarQuoteTag(s string) (string, bool) {
	if len(s) < 2 || s[0] != '$' {
		return "", false
	}
	if s[1] == '$' {
		return "$$", true
	}
	for i := 1; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '$':
			if i == 1 {
				return "", false
			}
			return s[:i+1], true
		case ch == '_' ||
			(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
			// allowed anywhere in the tag
		case ch >= '0' && ch <= '9':
			if i == 1 {
				return "", false // a tag may not start with a digit
			}
		default:
			return "", false
		}
	}
	return "", false
}
