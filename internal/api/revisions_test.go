// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"
)

func TestRevisionConfigPreviewMasksBeforeTrimming(t *testing.T) {
	raw := []byte("global\r\nhttp-request lua.easywaf_auth \"https://fixture.invalid/?token=private\"\n")
	want := `global http-request lua.easywaf_auth "***MASKED***"`
	if got := revisionConfigPreview(raw, false); got != want {
		t.Fatalf("preview did not mask the forward-auth target")
	}
	if got := revisionConfigPreview(raw[:len(raw)-2], true); got != `global http-request lua.easywaf_auth "***MASKED***…` {
		t.Fatal("preview did not mask a truncated forward-auth target")
	}
	runes := strings.Repeat("ф", revisionPreviewMaxRunes)
	if got := revisionConfigPreview([]byte(runes+"suffix"), false); got != runes+"…" {
		t.Fatal("preview did not truncate at a rune boundary")
	}
}
