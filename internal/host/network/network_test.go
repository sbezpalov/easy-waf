// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedNetplanState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "50-cloud-init.yaml"), []byte("installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, state := readNetplanFiles(dir)
	if state != "absent" || len(files) != 1 {
		t.Fatalf("installer only: %s, %d files", state, len(files))
	}
	managed := filepath.Join(dir, "99-easy-waf.yaml")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, state := readNetplanFiles(dir); state != "unavailable" {
		t.Fatalf("unreadable managed file: %s", state)
	}
	if err := os.Remove(managed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, state = readNetplanFiles(dir)
	if state != "readable" || len(files) != 2 || files[1].Content != "managed" {
		t.Fatalf("managed and installer files: %s, %d files", state, len(files))
	}
}
