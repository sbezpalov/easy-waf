// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func aptExecutionLeaseFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-only execution lease: run the Ubuntu container suite")
	}
	previous := stateDir
	stateDir = t.TempDir()
	t.Cleanup(func() { stateDir = previous })
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(stateDir, "apt-execution.lock")
}

func TestAPTExecutionLeaseExcludesStartsAndHonorsCancellation(t *testing.T) {
	path := aptExecutionLeaseFixture(t)
	if err := os.WriteFile(path, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := acquireAPTExecutionLease(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = release()
		}
	})
	if other, err := acquireAPTExecutionLease(t.Context(), false); other != nil || !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("another package execution bypassed the lease: release=%v err=%v", other != nil, err)
	}
	if code, err := (aptWorkerRunner{}).RunApt(t.Context(), "/nonexistent-apt-fixture-command", nil, func(string) error { return nil }); code != 1 || err == nil || !strings.Contains(err.Error(), "reserved for maintenance") {
		t.Fatalf("worker attempted execution while maintenance held its lease: code=%d error=%v", code, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if other, err := acquireAPTExecutionLease(ctx, true); other != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("maintenance wait lost cancellation: release=%v err=%v", other != nil, err)
	}
	if other, err := acquireAPTExecutionLease(t.Context(), false); other != nil || !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("canceled waiter released the current worker: release=%v err=%v", other != nil, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	released = true
	other, err := acquireAPTExecutionLease(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := other(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "sentinel\n" {
		t.Fatalf("lease file was truncated or changed: %q %v", data, err)
	}
}

func TestAPTExecutionLeaseRejectsUnsafeState(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "public_file", "public_directory"} {
		t.Run(kind, func(t *testing.T) {
			path := aptExecutionLeaseFixture(t)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "target"), path)
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "public_directory":
				err = os.Chmod(stateDir, 0o755)
			default:
				err = os.WriteFile(path, nil, 0o600)
				if err == nil && kind == "hardlink" {
					err = os.Link(path, path+".alias")
				} else if err == nil {
					err = os.Chmod(path, 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if release, err := acquireAPTExecutionLease(t.Context(), false); release != nil || err == nil {
				t.Fatalf("unsafe %s state acquired a lease: %v", kind, err)
			}
		})
	}
}

func TestAPTWorkerShutdownJoinsSynchronousMutationWithoutCancelingIt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root worker socket requires the Ubuntu root fixture")
	}
	t.Setenv("NOTIFY_SOCKET", "")
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	previous := DefaultRunner
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	DefaultRunner = &aptMutationRunner{run: func(ctx context.Context, _ string, _ []string, _ func(string) error) (int, error) {
		started <- ctx
		<-release
		return 0, ctx.Err()
	}}
	t.Cleanup(func() { DefaultRunner = previous })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	socket := shortTempSock(t)
	go func() { done <- serveSocket(ctx, socket, aptWorkerSocket) }()
	released, finished := false, false
	var client net.Conn
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		cancel()
		if client != nil {
			_ = client.Close()
		}
		if !finished {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("worker fixture did not join its package handler")
			}
		}
		resetAptUpgradeState()
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		client, err = net.DialTimeout("unix", socket, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if client == nil {
		t.Fatal("worker fixture did not start")
	}
	if err := json.NewEncoder(client).Encode(Request{Argv: []string{"apt-upgrade"}}); err != nil {
		t.Fatal(err)
	}
	var packageContext context.Context
	select {
	case packageContext = <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("synchronous mutation did not start")
	}
	cancel()
	select {
	case <-packageContext.Done():
		t.Fatal("worker shutdown canceled its package transaction")
	case err := <-done:
		finished = true
		t.Fatalf("worker exited before package completion: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	released = true
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker stayed alive after its package handler completed")
	}
}
