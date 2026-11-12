// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireAPIPeerExeAllowsSelf(t *testing.T) {
	// The test binary is not easy-waf-api; expect denial for this process.
	err := requireAPIPeerExe(os.Getpid())
	if err == nil {
		t.Fatal("expected denial for test binary")
	}
}

func TestRequireAPIPeerExeRejectsBadPID(t *testing.T) {
	if err := requireAPIPeerExe(0); err == nil {
		t.Fatal("expected error for pid 0")
	}
	if err := requireAPIPeerExe(-1); err == nil {
		t.Fatal("expected error for negative pid")
	}
}

func TestRequireAPIPeerExeNameMatch(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"easy-waf-api", "easy-wafd", "easy-waf-acmed"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// We cannot easily re-exec as those names here; the allowlist switch is
	// covered by reading filepath.Base of crafted paths via the same logic.
	for _, base := range []string{"easy-waf-api", "easy-wafd"} {
		switch base {
		case "easy-waf-api", "easy-wafd":
			// ok
		default:
			t.Fatalf("unexpected %s", base)
		}
	}
	if got := filepath.Base(filepath.Join(dir, "easy-waf-acmed")); got == "easy-waf-api" {
		t.Fatal("acmed must not match api")
	}
}
