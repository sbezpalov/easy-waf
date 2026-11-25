// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedConfigSizeBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.conf")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, MaxManagedConfigBytes); err != nil {
		t.Fatal(err)
	}
	if text, err := ReadManagedConfig(path); err != nil || len(text) != MaxManagedConfigBytes {
		t.Fatalf("at limit: read %d bytes, err %v", len(text), err)
	}
	if err := os.Truncate(path, MaxManagedConfigBytes+1); err != nil {
		t.Fatal(err)
	}
	if text, err := ReadManagedConfig(path); err == nil || text != "" {
		t.Fatalf("above limit: read %d bytes, err %v", len(text), err)
	}
}
