// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package ipwl

import "testing"

func TestFileHasEntries(t *testing.T) {
	if FileHasEntries([]byte("# only\n")) {
		t.Fatal("comment-only should be false")
	}
	if !FileHasEntries([]byte("# h\n10.0.0.1\n")) {
		t.Fatal("expected true with ip line")
	}
}
