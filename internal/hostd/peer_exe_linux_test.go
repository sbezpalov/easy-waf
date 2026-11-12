// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"os"
	"os/exec"
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

func TestRequireAPIPeerExeRejectsMatchingBasenameOutsideInstalledPath(t *testing.T) {
	if os.Getenv("EASY_WAF_PEER_EXE_CHILD") == "1" {
		select {}
	}

	path := t.TempDir() + "/easy-waf-api"
	input, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, input, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=TestRequireAPIPeerExeRejectsMatchingBasenameOutsideInstalledPath")
	cmd.Env = append(os.Environ(), "EASY_WAF_PEER_EXE_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if err := requireAPIPeerExe(cmd.Process.Pid); err == nil {
		t.Fatal("matching basename outside /usr/sbin must be rejected")
	}
}
