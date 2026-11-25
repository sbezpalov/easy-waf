// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestBundleSizeIncludesTarFooter(t *testing.T) {
	for _, limit := range []int{2047, 2048} {
		var output bytes.Buffer
		dst := &bundleWriter{dst: &output, remaining: limit}
		tw := tar.NewWriter(dst)
		if err := addTarBytes(tw, "manifest", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := tw.Close()
		if (err == nil) != (limit == 2048) || output.Len() > limit {
			t.Fatalf("limit %d: wrote %d bytes, close error %v", limit, output.Len(), err)
		}
	}
}

func TestBundleProbeCapture(t *testing.T) {
	if os.Getenv("EASY_WAF_TEST_BUNDLE_PROBE_CHILD") == "1" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), commandoutput.Limit))
		_, _ = os.Stderr.WriteString("extra")
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, combined := range []bool{false, true} {
		cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestBundleProbeCapture$") // #nosec G204 -- Re-execute only this test binary with a fixed test selector.
		cmd.Env = append(os.Environ(), "EASY_WAF_TEST_BUNDLE_PROBE_CHILD=1")
		out, err := probeOutput(cmd, combined)
		if err != nil {
			t.Fatal(err)
		}
		if combined {
			if string(out) != "(output omitted: probe exceeded 4194304 bytes)\n" {
				t.Fatalf("missing overflow marker, got %d bytes", len(out))
			}
		} else if len(out) != commandoutput.Limit || bytes.Count(out, []byte("x")) != len(out) {
			t.Fatal("stdout at the limit must be preserved without stderr")
		}
	}
}

func TestBundleMasksMultilineEnvironment(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is required for the real bundle integration test")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Setenv("EASY_WAF_JWT_SECRET", "fixture-sensitive-head\nfixture-sensitive-tail")
	t.Setenv("EASY_WAF_MCP_API_TOKEN", "fixture-sensitive-mcp-api")
	t.Setenv("EASY_WAF_MCP_TOKEN", "fixture-sensitive-mcp-client")
	fixture, err := os.ReadFile(filepath.Join("testdata", "environment-multiline.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "environment-multiline.masked.example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"file", "process_fallback", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			state := t.TempDir()
			env := filepath.Join(state, "appliance.env")
			if kind == "file" {
				if err := os.WriteFile(env, fixture, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "oversized" {
				dir, cfg, list := haproxy.Paths(state)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{env, cfg, list} {
					if err := os.WriteFile(path, []byte("fixture-sensitive-file-prefix\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Truncate(path, hostspec.MaxManagedConfigBytes+1); err != nil {
						t.Fatal(err)
					}
				}
			}
			body, err := BuildSupportBundleGzip(t.Context(), Params{
				StateDir: state, EnvPath: env, Store: st, Settings: config.DefaultSettings(state),
			})
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gz.Close() }()
			reader := tar.NewReader(gz)
			found, foundMCP := false, false
			oversizedEntries := 0
			for {
				hdr, err := reader.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(io.LimitReader(reader, MaxBundleBytes+1))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "fixture-sensitive") || strings.Contains(string(data), dsn) {
					t.Fatal("support archive leaked a multiline secret or database URL")
				}
				if strings.HasSuffix(hdr.Name, "/config/easy-waf.env.masked") {
					found = true
					if kind == "file" && string(data) != string(want) {
						t.Fatal("bundle environment differs from shared redaction fixture")
					}
				}
				if strings.HasSuffix(hdr.Name, "/systemctl/state-easy-waf-mcpd.txt") {
					foundMCP = true
				}
				if kind == "oversized" && (strings.HasSuffix(hdr.Name, "/config/easy-waf.env.masked") ||
					strings.HasSuffix(hdr.Name, "/config/haproxy.cfg") || strings.HasSuffix(hdr.Name, "/config/crt-list-filenames.txt") ||
					strings.HasSuffix(hdr.Name, "/validation/haproxy-check.txt")) {
					if !bytes.Contains(data, []byte("exceeds")) {
						t.Fatalf("missing size notice in %s", hdr.Name)
					}
					oversizedEntries++
				}
			}
			if kind == "oversized" && oversizedEntries != 4 {
				t.Fatalf("found %d size notices", oversizedEntries)
			}
			if !found || !foundMCP {
				t.Fatal("bundle missing masked environment or MCP service state")
			}
			// tar EOF precedes the gzip checksum. Require a clean end of stream.
			var trailing [1]byte
			if n, err := gz.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("unexpected gzip trailer: n=%d err=%v", n, err)
			}
		})
	}
}

func TestMCPServiceStateUsesOnlySelectedProperties(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd probe fixture requires a POSIX script")
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	script := `#!/bin/sh
if [ "$*" != 'show --no-pager -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result -p ConditionResult -p ExecMainStatus easy-waf-mcpd.service' ]; then
  exit 91
fi
printf 'fixture-sensitive-mcp-stderr\n' >&2
if [ "$MCP_STATE_TEST_FAIL" = yes ]; then
  printf 'fixture-sensitive-mcp-partial-output\n'
  exit 1
fi
printf 'LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nConditionResult=no\n'
`
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0o700); err != nil { // #nosec G306 -- Owner-only executable in a private test directory.
		t.Fatal(err)
	}
	t.Setenv("MCP_STATE_TEST_FAIL", "no")
	if got := string(mcpServiceState(t.Context())); got != "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nConditionResult=no\n" {
		t.Fatal("MCP service state did not contain exactly the selected properties")
	}
	t.Setenv("MCP_STATE_TEST_FAIL", "yes")
	if got := string(mcpServiceState(t.Context())); got != "MCP service state unavailable\n" {
		t.Fatal("failed MCP state command did not return only the unavailable marker")
	}
}

func TestBuildSupportBundleGzip_nilStore(t *testing.T) {
	_, err := BuildSupportBundleGzip(context.Background(), Params{})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestManagedHAProxyConfigPath(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.WriteFile(inside, []byte("global\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := managedHAProxyConfigPath(stateDir, inside)
	want, resolveErr := filepath.EvalSymlinks(inside)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if err != nil || got != want {
		t.Fatalf("got %q err %v", got, err)
	}
	missing := filepath.Join(managedDir, "missing.cfg")
	if got, err := managedHAProxyConfigPath(stateDir, missing); err != nil || got != missing {
		t.Fatalf("missing managed path: got %q err %v", got, err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, "/etc/passwd"); err == nil {
		t.Fatal("expected path outside state directory to fail")
	}
}

func TestManagedHAProxyConfigPathRejectsEscapingSymlink(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.cfg")
	if err := os.WriteFile(outside, []byte("global\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, link); err == nil {
		t.Fatal("expected escaping symlink to fail")
	}
}

func TestManagedHAProxyConfigPathRejectsDanglingSymlink(t *testing.T) {
	stateDir := t.TempDir()
	managedDir := filepath.Join(stateDir, "haproxy")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(managedDir, "haproxy.cfg")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.cfg"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := managedHAProxyConfigPath(stateDir, link); err == nil {
		t.Fatal("expected dangling symlink to fail closed")
	}
}

func TestProcessEnvSnapshotMasksSecretsAndSkipsOtherVariables(t *testing.T) {
	t.Setenv("EASY_WAF_LISTEN_HTTPS", "0.0.0.0:8443")
	t.Setenv("EASY_WAF_ADMIN_TOKEN", "super-secret-token")
	t.Setenv("DATABASE_URL", "postgres://easywaf:db-password@127.0.0.1:5432/easywaf")
	t.Setenv("UNRELATED_SECRET_VALUE", "must-not-appear")

	out := string(MaskEasyWAFEnvContent(processEnvSnapshot("/etc/easy-waf/easy-waf.env", errors.New("permission denied"))))

	if !strings.Contains(out, "EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443") {
		t.Errorf("settings missing:\n%s", out)
	}
	for _, leaked := range []string{"super-secret-token", "db-password", "must-not-appear"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q leaked:\n%s", leaked, out)
		}
	}
}

func TestProcessEnvSnapshotPreservesEntryBoundaries(t *testing.T) {
	t.Setenv("EASY_WAF_JWT_SECRET", "fixture-head\nfixture-sensitive-env-tail")
	t.Setenv("EASY_WAF_PUBLIC_NOTE", "first\nFAKE_ENTRY=public-tail\rvalue")
	raw := processEnvSnapshot("/missing/env", errors.New("permission denied"))
	if strings.Contains(string(raw), "fixture-sensitive-env-tail") {
		t.Error("snapshot flattened a secret before masking")
	}
	if !strings.Contains(string(raw), "EASY_WAF_PUBLIC_NOTE=first\\nFAKE_ENTRY=public-tail\\rvalue") {
		t.Error("snapshot did not escape public value line boundaries")
	}
	if strings.Contains(string(MaskEasyWAFEnvContent(raw)), "fixture-sensitive-env-tail") {
		t.Fatal("final environment copy leaked a secret suffix")
	}
}
