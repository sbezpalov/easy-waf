// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestHAProxyStatsSocketPathFromGeneratedConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "haproxy.cfg")
	body := "global\n" +
		"\tlog /dev/log local0\n" +
		"\tstats socket /run/haproxy/easy-waf-admin.sock mode 660 level admin expose-fd listeners\n" +
		"\tstats timeout 30s\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, src := haproxyStatsSocketPath(cfg)
	if got != "/run/haproxy/easy-waf-admin.sock" {
		t.Fatalf("path = %q, want the socket from the config", got)
	}
	// The options after the path are HAProxy's, not part of the path.
	if strings.Contains(got, " ") {
		t.Fatalf("path %q swallowed the socket options", got)
	}
	if !strings.Contains(src, cfg) {
		t.Fatalf("source %q does not say where the answer came from", src)
	}
}

func TestHAProxyStatsSocketPathFallsBackToDefault(t *testing.T) {
	// A missing config, and a config with no stats socket line, both fall back to
	// the current default — not to /run/haproxy/admin.sock, which is the legacy
	// path this check used to probe and which no appliance has created for
	// several releases.
	want := config.DefaultSettings("").HAProxyStatsSocketPath
	if want == "/run/haproxy/admin.sock" {
		t.Fatal("the default is the legacy path; this test no longer proves anything")
	}

	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.cfg")
	if got, src := haproxyStatsSocketPath(missing); got != want || !strings.Contains(src, "default") {
		t.Fatalf("missing config: got %q (%s), want %q", got, src, want)
	}

	noSocket := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(noSocket, []byte("global\n\tdaemon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, src := haproxyStatsSocketPath(noSocket); got != want || !strings.Contains(src, "default") {
		t.Fatalf("config without a stats socket: got %q (%s), want %q", got, src, want)
	}
}
