// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCollectRoutes(t *testing.T) {
	v4 := `{"dst":"default","gateway":"192.0.2.1"}`
	v6 := `{"dst":"default","gateway":"fe80::1"}`
	for _, tc := range []struct {
		name, ipv4, ipv6 string
		want             []string
	}{
		{"dual stack", "[" + v4 + "]", "[" + v6 + "]", []string{v4, v6}},
		{"IPv6 disabled", "[" + v4 + "]", "", []string{v4}},
		{"invalid IPv4 snapshot", "invalid", "[" + v6 + "]", []string{v6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := collectRoutes(func(family string) ([]byte, error) {
				switch family {
				case "-4":
					return []byte(tc.ipv4), nil
				case "-6":
					if tc.ipv6 == "" {
						return nil, os.ErrNotExist
					}
					return []byte(tc.ipv6), nil
				}
				t.Fatalf("unexpected family %s", family)
				return nil, nil
			})
			got := make([]string, 0, len(rows))
			for _, row := range rows {
				got = append(got, string(row))
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

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
	if state != "absent" || len(files) != 0 {
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
	if state != "readable" || len(files) != 1 || files[0].Path != managed || files[0].Content != "managed" {
		t.Fatalf("managed and installer files: %s, %d files", state, len(files))
	}
}

func TestManagedNetplanSymlink(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "50-cloud-init.yaml")
	if err := os.WriteFile(other, []byte("installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "99-easy-waf.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if files, state := readNetplanFiles(dir); state != "unavailable" || len(files) != 0 {
		t.Fatalf("managed symlink: %s, %d files", state, len(files))
	}
}
