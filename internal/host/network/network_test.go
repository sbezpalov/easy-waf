// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseResolverDNS(t *testing.T) {
	output := "Global: 192.0.2.1 192.0.2.2\n" +
		"        2001:db8::53\nLink 1 (lo):\n" +
		"Link 2 (eth0): [2001:db8::1]:853#dns.example\n" +
		"        fe80::53%eth0\nLink 3 (eth1): 198.51.100.53"
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::53", "[2001:db8::1]:853#dns.example", "fe80::53%eth0", "198.51.100.53"}
	if got := parseResolverDNS(output); !slices.Equal(got, want) {
		t.Fatalf("DNS servers: got %q, want %q", got, want)
	}
	if got := parseResolverDNS("Global:\nLink 1 (lo):\n"); len(got) != 0 {
		t.Fatalf("empty resolver configuration returned %q", got)
	}
}

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
