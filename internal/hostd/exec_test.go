package hostd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyFile_atomicReplace(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("table inet easy_waf {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old ruleset\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst, 0o644); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "table inet easy_waf {}\n" {
		t.Fatalf("destination content = %q", got)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("destination mode = %o, want 0644", fi.Mode().Perm())
	}

	// The temporary file must not survive a successful copy.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// A failed copy must leave the previous file intact rather than a truncated one:
// this is the rollback path for the live nftables ruleset.
func TestCopyFile_keepsDestinationWhenSourceMissing(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("old ruleset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(filepath.Join(dir, "missing"), dst, 0o644); err == nil {
		t.Fatal("expected an error for a missing source")
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "old ruleset\n" {
		t.Fatalf("destination was disturbed: %q, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("failed copy left %d files behind", len(entries))
	}
}
