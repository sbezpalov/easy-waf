// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenStoreRefusesAnEmptyConfiguredDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "fixture malformed inherited conninfo")
	path := filepath.Join(t.TempDir(), "easy-waf.env")
	if err := os.WriteFile(path, []byte("DATABASE_URL=fixture malformed older conninfo\nDATABASE_URL=\"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := openStoreFromEnvFile(path, "")
	if st != nil {
		_ = st.Close()
	}
	if st != nil || err == nil || !strings.Contains(err.Error(), "DATABASE_URL is empty") {
		t.Fatal("a cleared file entry must stop the CLI before opening a database")
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
