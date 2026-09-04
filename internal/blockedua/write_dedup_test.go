// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package blockedua

import (
	"reflect"
	"testing"
)

// The map file is regenerated from the database on every apply, so duplicate
// rows (the same pattern added twice) must not become duplicate map lines.
func TestNormalizePatterns(t *testing.T) {
	got := normalizePatterns([]string{"  curl/7  ", "curl/7", "# comment", "", "zgrab", "curl/7", "  ", "zgrab"})
	want := []string{"curl/7", "zgrab"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizePatterns = %q, want %q", got, want)
	}
}

func TestNormalizePatterns_sortsAndKeepsDistinctCase(t *testing.T) {
	got := normalizePatterns([]string{"zgrab", "Curl", "curl"})
	want := []string{"Curl", "curl", "zgrab"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizePatterns = %q, want %q", got, want)
	}
}

func TestNormalizePatterns_empty(t *testing.T) {
	if got := normalizePatterns(nil); len(got) != 0 {
		t.Fatalf("expected no patterns, got %q", got)
	}
	if got := normalizePatterns([]string{"", "  ", "# only comments"}); len(got) != 0 {
		t.Fatalf("expected no patterns, got %q", got)
	}
}
