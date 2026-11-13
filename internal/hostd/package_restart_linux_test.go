// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPackageRestartSignalProcessHelper(t *testing.T) {
	dir := os.Getenv("EASY_WAF_PACKAGE_RESTART_SIGNAL_TEST_DIR")
	if dir == "" {
		return
	}
	ctx, stop := packageRestartWaitContext()
	defer stop()
	runner := packageRestartRunner(func(jobCtx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
		if err := os.WriteFile(filepath.Join(dir, "job-ready"), []byte("ready"), 0o600); err != nil {
			return nil, nil, 1, err
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			return nil, nil, 1, errors.New("fixture did not receive TERM")
		}
		if err := os.WriteFile(filepath.Join(dir, "signal-seen"), []byte("seen"), 0o600); err != nil {
			return nil, nil, 1, err
		}
		limit := time.Now().Add(10 * time.Second)
		for time.Now().Before(limit) {
			if err := jobCtx.Err(); err != nil {
				return nil, nil, 1, fmt.Errorf("signal interrupted submitted job: %w", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "release-job")); err == nil {
				return nil, nil, 0, nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return nil, nil, 1, errors.New("fixture job was not released")
	})
	err := restartBrokerAfterPackages(ctx, runner, func(ctx context.Context) (func() error, error) {
		return acquirePackageLocks(ctx, dir, packageLockOwner(t, dir))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPackageRestartTERMRetainsLocksUntilSubmittedJobFinishes(t *testing.T) {
	dir := packageLockFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPackageRestartSignalProcessHelper$")
	cmd.Env = append(os.Environ(), "EASY_WAF_PACKAGE_RESTART_SIGNAL_TEST_DIR="+dir,
		"TMPDIR="+dir, "TMP="+dir, "TEMP="+dir)
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	finished := false
	t.Cleanup(func() {
		defer cancel()
		_ = os.WriteFile(filepath.Join(dir, "release-job"), []byte("release"), 0o600)
		if !finished {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("signal fixture cleanup: %v", err)
			}
		}
	})
	waitCommandFixture(t, filepath.Join(dir, "job-ready"))
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitCommandFixture(t, filepath.Join(dir, "signal-seen"))
	for _, name := range []string{"lock-frontend", "lock"} {
		probePackageLock(t, filepath.Join(dir, name), "busy")
	}
	if err := os.WriteFile(filepath.Join(dir, "release-job"), []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		finished = true
		t.Fatal(err)
	}
	finished = true
	for _, name := range []string{"lock-frontend", "lock"} {
		probePackageLock(t, filepath.Join(dir, name), "unlocked")
	}
}

// Only this test executable is spawned. Paths are supplied by its parent's
// owned temporary fixture, never the appliance's actual dpkg database.
func TestPackageLockProcessHelper(t *testing.T) {
	path := os.Getenv("EASY_WAF_PACKAGE_LOCK_TEST_FILE")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(unix.SEEK_SET)}
	err = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
	if os.Getenv("EASY_WAF_PACKAGE_LOCK_TEST_MODE") == "probe" {
		switch {
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EACCES):
			fmt.Println("busy")
		case err == nil:
			fmt.Println("unlocked")
		default:
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".ready", []byte("locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(20 * time.Second)
	for time.Now().Before(limit) {
		if _, err := os.Stat(path + ".release"); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("package lock fixture was not released")
}

func packageLockFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"lock-frontend", "lock"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("sentinel\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func packageLockOwner(t *testing.T, dir string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return st.Uid
}

func packageLockChild(ctx context.Context, t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPackageLockProcessHelper$")
	cmd.Env = append(os.Environ(), "EASY_WAF_PACKAGE_LOCK_TEST_FILE="+path, "EASY_WAF_PACKAGE_LOCK_TEST_MODE="+mode,
		"TMPDIR="+filepath.Dir(path), "TMP="+filepath.Dir(path), "TEMP="+filepath.Dir(path))
	return cmd
}

func holdPackageLock(t *testing.T, path string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := packageLockChild(ctx, t, path, "hold")
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	release := func() {
		once.Do(func() {
			defer cancel()
			_ = os.WriteFile(path+".release", []byte("release"), 0o600)
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("lock holder: %v", err)
				}
			case <-time.After(3 * time.Second):
				cancel()
				waitErr := <-done
				t.Errorf("lock holder needed cancellation to exit: %v", waitErr)
			}
		})
	}
	t.Cleanup(release)
	waitCommandFixture(t, path+".ready")
	return release
}

func probePackageLock(t *testing.T, path, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	data, err := packageLockChild(ctx, t, path, "probe").CombinedOutput()
	if err != nil || !strings.Contains(string(data), want+"\n") {
		t.Errorf("kernel lock probe %s: want=%s output=%q err=%v", filepath.Base(path), want, data, err)
	}
}

func TestPackageRestartWaitsForActualFrontendAndBackendLocks(t *testing.T) {
	for _, name := range []string{"lock-frontend", "lock"} {
		t.Run(name, func(t *testing.T) {
			dir := packageLockFixture(t)
			owner := packageLockOwner(t, dir)
			releaseChild := holdPackageLock(t, filepath.Join(dir, name))
			called := make(chan struct{}, 1)
			runner := packageRestartRunner(func(context.Context, string, ...string) ([]byte, []byte, int, error) {
				for _, path := range []string{"lock-frontend", "lock"} {
					probePackageLock(t, filepath.Join(dir, path), "busy")
				}
				called <- struct{}{}
				return nil, nil, 0, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- restartBrokerAfterPackages(ctx, runner, func(ctx context.Context) (func() error, error) {
					return acquirePackageLocks(ctx, dir, owner)
				})
			}()
			select {
			case <-called:
				t.Fatal("restart ran before the package transaction released its lock")
			case <-time.After(50 * time.Millisecond):
			}
			releaseChild()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			select {
			case <-called:
			default:
				t.Fatal("restart never ran")
			}
			for _, path := range []string{"lock-frontend", "lock"} {
				probePackageLock(t, filepath.Join(dir, path), "unlocked")
				if data, err := os.ReadFile(filepath.Join(dir, path)); err != nil || string(data) != "sentinel\n" {
					t.Fatalf("helper changed package lock contents: %q %v", data, err)
				}
			}
		})
	}
}

func TestPackageLockCancellationReleasesEarlierLocks(t *testing.T) {
	dir := packageLockFixture(t)
	_ = holdPackageLock(t, filepath.Join(dir, "lock"))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if release, err := acquirePackageLocks(ctx, dir, packageLockOwner(t, dir)); release != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait lost cancellation: release=%v err=%v", release != nil, err)
	}
	probePackageLock(t, filepath.Join(dir, "lock-frontend"), "unlocked")
}

func TestPackageLockRejectsReplacementDuringWait(t *testing.T) {
	dir := packageLockFixture(t)
	owner := packageLockOwner(t, dir)
	path := filepath.Join(dir, "lock")
	releaseChild := holdPackageLock(t, path)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := acquirePackageLocks(ctx, dir, owner)
		if release != nil {
			_ = release()
		}
		done <- err
	}()
	// Prove the helper has pinned/opened both files and is waiting on backend:
	// it must hold frontend, not merely be an unscheduled goroutine.
	limit := time.Now().Add(2 * time.Second)
	for {
		data, err := packageLockChild(ctx, t, filepath.Join(dir, "lock-frontend"), "probe").CombinedOutput()
		if err == nil && strings.Contains(string(data), "busy\n") {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("helper did not acquire frontend before backend wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	releaseChild()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "changed while waiting") {
		t.Fatalf("stale inode authorized a restart: %v", err)
	}
	probePackageLock(t, filepath.Join(dir, "lock-frontend"), "unlocked")
}

func TestPackageLocksRejectUnsafeOrMissingFiles(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "hardlink", "fifo", "directory", "writable", "directory_writable", "directory_symlink", "wrong_owner"} {
		t.Run(kind, func(t *testing.T) {
			dir := packageLockFixture(t)
			path := filepath.Join(dir, "lock")
			owner := packageLockOwner(t, dir)
			switch kind {
			case "missing", "symlink", "fifo", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(filepath.Join(dir, "lock-frontend"), path)
				case "fifo":
					err = unix.Mkfifo(path, 0o600)
				case "directory":
					err = os.Mkdir(path, 0o700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "directory_writable":
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			case "directory_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				dir = alias
			case "wrong_owner":
				owner++
			}
			if release, err := acquirePackageLocks(t.Context(), dir, owner); err == nil || release != nil {
				if release != nil {
					_ = release()
				}
				t.Fatalf("unsafe %s lock accepted: %v", kind, err)
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("helper created the missing package lock")
				}
			}
		})
	}
}
