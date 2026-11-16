// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apply

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealHAProxyValidationFromPrivateWorkingDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for HAProxy's real UID/GID transition")
	}
	binary, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("HAProxy not installed")
	}
	if _, err := user.Lookup("haproxy"); err != nil {
		t.Skip("HAProxy OS account not present")
	}
	if _, err := user.LookupGroup("haproxy"); err != nil {
		t.Skip("HAProxy OS group not present")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "fixture.cfg")
	body := "global\n  user haproxy\n  group haproxy\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend fixture\n  bind 127.0.0.1:18089\n  http-request deny deny_status 503\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	output, bareErr := exec.CommandContext(t.Context(), binary, "-c", "-f", config).CombinedOutput()
	if bareErr != nil && (strings.Contains(string(output), "Cannot set uid") || strings.Contains(string(output), "Cannot set gid")) {
		t.Skip("root fixture lacks permission for HAProxy UID/GID transition")
	}
	if bareErr != nil && !strings.Contains(string(output), "Impossible to get back to initial directory") {
		t.Fatalf("unexpected bare HAProxy error: %v: %s", bareErr, output)
	}
	if err := Validate(t.Context(), binary, "fixture.cfg"); err != nil {
		t.Fatalf("real HAProxy validation from private cwd: %v", err)
	}
}
