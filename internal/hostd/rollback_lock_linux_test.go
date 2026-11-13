// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRollbackLockAcrossProcesses(t *testing.T) {
	if dir := os.Getenv("EASY_WAF_ROLLBACK_LOCK_CHILD"); dir != "" {
		stateDir = dir
		unlock, err := lockRollback(false)
		if os.Getenv("EASY_WAF_ROLLBACK_EXPECT_BUSY") == "1" {
			if err == nil {
				unlock()
				t.Fatal("child acquired the broker's held lock")
			}
			if !strings.Contains(err.Error(), "busy") {
				t.Fatal(err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			unlock()
		}
		return
	}
	rollbackTestEnv(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	checkChild := func(busy string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRollbackLockAcrossProcesses$")
		cmd.Env = append(os.Environ(), "EASY_WAF_ROLLBACK_LOCK_CHILD="+stateDir, "EASY_WAF_ROLLBACK_EXPECT_BUSY="+busy)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
	}
	func() {
		unlock, err := lockRollback(false)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		checkChild("1")
	}()
	checkChild("0")
}
