// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetDatabaseDSNReadsEnvFile(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	path := filepath.Join(t.TempDir(), "easy-waf.env")
	const want = "postgres://from-file/db"
	if err := os.WriteFile(path, []byte("DATABASE_URL="+want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveDSNForWipe(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got, err = resolveDSNForWipe(path, "postgres://from-flag/db")
	if err != nil {
		t.Fatal(err)
	}
	if got != "postgres://from-flag/db" {
		t.Fatalf("flag override: got %q", got)
	}
}

func TestWipeCommandsResolveDSNFromEnvFile(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fn := range []string{"func factoryReset()", "func resetAppliance()"} {
		i := strings.Index(text, fn)
		if i < 0 {
			t.Fatalf("missing %s", fn)
		}
		rest := text[i+len(fn):]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		if strings.Contains(strings.ReplaceAll(rest, "openStoreFromEnvFile(", ""), "openStoreFrom(") {
			t.Fatalf("%s ignores -env-file and reads only the process environment", fn)
		}
		if !strings.Contains(rest, "openStoreFromEnvFile(") {
			t.Fatalf("%s does not resolve DATABASE_URL from -env-file", fn)
		}
	}
}
