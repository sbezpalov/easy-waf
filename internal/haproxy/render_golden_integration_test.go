// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package haproxy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoldenConfigsPassHaproxyCheck requires:
//   - haproxy in PATH
//   - cwd = internal/haproxy (normal for go test ./internal/haproxy)
//   - committed testdata/golden/*.cfg, *.crt-list.txt, certs, spoe, ipbl
func TestGoldenConfigsPassHaproxyCheck(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH (install haproxy to run integration golden validation)")
	}
	goldenDir, err := filepath.Abs(filepath.Join("testdata", "golden"))
	if err != nil {
		t.Fatal(err)
	}
	fixturePaths := func(body []byte) []byte {
		return bytes.ReplaceAll(body, []byte("testdata/golden/"), []byte(filepath.ToSlash(goldenDir)+"/"))
	}

	for _, name := range goldenScenarioNames {
		t.Run(name, func(t *testing.T) {
			cfgPath := filepath.Join("testdata", "golden", name+".cfg")
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			// HAProxy 3.x requires an absolute stats socket path, but sun_path is limited (~97 bytes).
			// t.TempDir() already includes a long test name; keep socket filename very short.
			d := t.TempDir()
			// The appliance validator runs from a traversable directory.
			// Materialize the list with absolute PEM paths, and resolve shared
			// SPOE/map fixtures without depending on HAProxy's working directory.
			listName := name + ".crt-list.txt"
			list, err := os.ReadFile(filepath.Join(goldenDir, listName))
			if err != nil {
				t.Fatal(err)
			}
			listPath := filepath.Join(d, "crt-list.txt")
			if err := os.WriteFile(listPath, fixturePaths(list), 0o600); err != nil {
				t.Fatal(err)
			}
			raw = fixturePaths(raw)
			raw = bytes.ReplaceAll(raw, []byte(filepath.ToSlash(filepath.Join(goldenDir, listName))), []byte(filepath.ToSlash(listPath)))
			absSock := filepath.Join(d, "s.sock")
			cfgBody := rewriteStatsSocketPathForHAProxyCheck(raw, absSock)
			// Backend-TLS fixtures record an operator CA path that exists only on the
			// appliance they were written for, and haproxy -c opens ca-file for real.
			cfgBody = rewriteCAFilePathForHAProxyCheck(cfgBody, goldenCAFileForCheck(t, d))
			// The packaged Lua file is not installed on a build machine.
			luaPath := filepath.Join(d, "forward-auth.lua")
			if err := os.WriteFile(luaPath, []byte(ForwardAuthLua), 0o600); err != nil {
				t.Fatal(err)
			}
			cfgBody = bytes.ReplaceAll(cfgBody, []byte(DefaultForwardAuthLuaPath), []byte(luaPath))
			tmp := filepath.Join(d, "c.cfg")
			if err := os.WriteFile(tmp, cfgBody, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), hx, "-c", "-f", tmp)
			cmd.Dir = filepath.VolumeName(tmp) + string(filepath.Separator)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("haproxy -c: %v\n%s", err, output)
			}
			if bytes.Contains(output, []byte("'option forwardfor' ignored")) {
				t.Fatalf("HTTP forwarding option inherited by a TCP section:\n%s", output)
			}
		})
	}
}

// goldenCAFileForCheck materializes a CA bundle for `haproxy -c` to open.
// TestMain has already written the throwaway bundle this copies.
func goldenCAFileForCheck(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join("testdata", "golden", "certs", "bundle-a.pem")
	pem, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read CA fixture %s: %v", src, err)
	}
	dst := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(dst, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}
