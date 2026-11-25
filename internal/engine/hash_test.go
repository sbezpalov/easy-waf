// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashArtifactRegularFiles(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"multibuffer", strings.Repeat("backend fixture\n", 9000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			data := []byte(tc.content)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			want := sha256HexBytes(data)
			if got, err := sha256HexFile(path); err != nil || got != want {
				t.Fatalf("hash = %q, err = %v, want %q", got, err, want)
			}
			link := path + ".link"
			if err := os.Symlink(path, link); err == nil {
				if got, err := sha256HexFile(link); err != nil || got != want {
					t.Fatalf("symlink hash = %q, err = %v, want %q", got, err, want)
				}
			}
		})
	}
	if _, err := sha256HexFile(dir); err == nil {
		t.Fatal("directory cannot be an artifact")
	}
	if _, err := sha256HexFile(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing artifact error = %v", err)
	}
}
