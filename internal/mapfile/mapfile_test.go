// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mapfile

import "testing"

func TestHasEntries(t *testing.T) {
	cases := map[string]bool{
		"":                          false,
		"\n\n":                      false,
		"# only a header\n":         false,
		"  # indented comment \n":   false,
		"# header\n10.0.0.1\n":      true,
		"10.0.0.0/8":                true,
		"\n\n  curl/7  \n":          true,
		"# a\n# b\n\n":              false,
		"# header\n\n# more\nzgrab": true,
	}
	for in, want := range cases {
		if got := HasEntries([]byte(in)); got != want {
			t.Fatalf("HasEntries(%q) = %v, want %v", in, got, want)
		}
	}
}
