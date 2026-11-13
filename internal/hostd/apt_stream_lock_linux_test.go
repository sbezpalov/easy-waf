// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDpkgHintDetectsPOSIXLocksWithoutConfusingFlock(t *testing.T) {
	path := filepath.Join(packageLockFixture(t), "lock-frontend")
	if dpkgLockFileBusy(path) {
		t.Fatal("unlocked package lock reported busy")
	}
	release := holdPackageLock(t, path)
	if !dpkgLockFileBusy(path) {
		t.Error("real POSIX lock held by a separate process was missed")
	}
	release()
	if dpkgLockFileBusy(path) {
		t.Fatal("released package lock still reported busy")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if dpkgLockFileBusy(path) {
		t.Error("unrelated flock was mistaken for an APT record lock")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "sentinel\n" {
		t.Fatalf("advisory inspection changed lock contents: %q %v", data, err)
	}
}

func TestDpkgHintTreatsUnsafeOrMissingFilesAsBusy(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock-frontend")
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "symlink":
				err = os.Symlink(filepath.Join(packageLockFixture(t), "lock-frontend"), path)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !dpkgLockFileBusy(path) {
				t.Fatalf("unsafe %s input reported unlocked", kind)
			}
		})
	}
}

func TestDispatchAptUpgradeStream_dpkgLockHint(t *testing.T) {
	resetAptUpgradeState()
	SetAptUpgradeStreamHookForTest(func(_ context.Context, _ func(string) error) (int, error) {
		return 0, nil
	})
	dpkgLockBusyHook = func() bool { return true }
	defer func() {
		dpkgLockBusyHook = nil
		resetAptUpgradeState()
	}()

	pr, pw := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw)
		_ = pw.Close()
	}()
	events := readStreamEvents(t, pr)
	found := false
	for _, ev := range events {
		if ev.Type == "line" && strings.Contains(ev.Data, "apt is locked") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lock hint missing: %+v", events)
	}
}
