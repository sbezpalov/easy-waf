// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")
	data := []byte("hello atomic world")

	if err := WriteAtomic(path, data, 0o600); err != nil {
		t.Fatalf("WriteAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", string(got), string(data))
	}
}
