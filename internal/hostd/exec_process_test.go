// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The helper is always this test executable, never a system command. A hard
// fixture lifetime also bounds stray children if the test itself is interrupted.
func TestHostdCommandProcessHelper(_ *testing.T) {
	mode := os.Getenv("EASY_WAF_EXEC_TEST_MODE")
	if mode == "" {
		return
	}
	dir := os.Getenv("EASY_WAF_EXEC_TEST_DIR")
	write := func(name, value string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			os.Exit(91)
		}
	}
	if mode == "burst" {
		for range 128 {
			_, _ = fmt.Fprintln(os.Stdout, "fixture stdout "+strings.Repeat("o", 4096))
			_, _ = fmt.Fprintln(os.Stderr, "fixture stderr "+strings.Repeat("e", 4096))
		}
		os.Exit(0)
	}
	if mode == "capture-overflow" || mode == "overflow-inherited" {
		for range 256 {
			if _, err := os.Stdout.WriteString(strings.Repeat("o", 32<<10)); err != nil {
				os.Exit(95)
			}
			if _, err := os.Stderr.WriteString(strings.Repeat("e", 32<<10)); err != nil {
				os.Exit(96)
			}
		}
		write("output-drained", "ready")
		if os.Getenv("EASY_WAF_EXEC_TEST_WAIT") == "1" {
			time.Sleep(30 * time.Second)
		}
		if mode == "capture-overflow" {
			code, _ := strconv.Atoi(os.Getenv("EASY_WAF_EXEC_TEST_EXIT"))
			os.Exit(code)
		}
		mode = "inherited"
	}
	if mode == "exit" {
		_, _ = fmt.Fprintln(os.Stdout, "captured stdout")
		_, _ = fmt.Fprintln(os.Stderr, "captured stderr")
		code, _ := strconv.Atoi(os.Getenv("EASY_WAF_EXEC_TEST_EXIT"))
		os.Exit(code)
	}
	if mode == "descendant" {
		write("child-ready", "ready")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if mode == "inherited" || mode == "closed" || mode == "cancel-tree" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(92)
		}
		child := exec.Command(executable, "-test.run=^TestHostdCommandProcessHelper$")
		child.Env = append(os.Environ(), "EASY_WAF_EXEC_TEST_MODE=descendant")
		if mode != "closed" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if err := child.Start(); err != nil {
			os.Exit(93)
		}
		write("child-pid", strconv.Itoa(child.Process.Pid))
		limit := time.Now().Add(20 * time.Second)
		for time.Now().Before(limit) {
			if _, err := os.Stat(filepath.Join(dir, "child-ready")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		write("ready", "ready")
		for time.Now().Before(limit) {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				if mode == "cancel-tree" {
					time.Sleep(30 * time.Second)
				}
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(94)
	}
	_, _ = fmt.Fprintln(os.Stdout, "before cancellation")
	write("ready", "ready")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func commandProcessFixture(t *testing.T, mode string) (string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("EASY_WAF_EXEC_TEST_MODE", mode)
	t.Setenv("EASY_WAF_EXEC_TEST_DIR", dir)
	// Helper TestMain creates bookkeeping; keep it in this fixture too.
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, dir)
	}
	return executable, dir
}

func waitCommandFixture(t *testing.T, path string) []byte {
	t.Helper()
	limit := time.Now().Add(10 * time.Second)
	for time.Now().Before(limit) {
		if data, err := os.ReadFile(path); err == nil && len(data) != 0 {
			return data
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("command fixture did not become ready: %s", filepath.Base(path))
	return nil
}

func TestOSRunnerPreservesNormalOutputAndExitStatus(t *testing.T) {
	for _, code := range []int{0, 7} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			executable, _ := commandProcessFixture(t, "exit")
			t.Setenv("EASY_WAF_EXEC_TEST_EXIT", strconv.Itoa(code))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			out, stderr, got, err := runCmd(ctx, osRunner{}, executable, "-test.run=^TestHostdCommandProcessHelper$")
			if err != nil || got != code || string(out) != "captured stdout\n" || string(stderr) != "captured stderr\n" {
				t.Fatalf("command result changed: code=%d out=%q stderr=%q err=%v", got, out, stderr, err)
			}
		})
	}
}

func TestOSRunnerPreservesCancellationCause(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			executable, dir := commandProcessFixture(t, "wait")
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 3*time.Second)
			}
			defer cancel()
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				_, _, code, err := runCmd(ctx, osRunner{}, executable, "-test.run=^TestHostdCommandProcessHelper$")
				done <- result{code, err}
			}()
			waitCommandFixture(t, filepath.Join(dir, "ready"))
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			} else {
				cancel()
			}
			select {
			case got := <-done:
				if got.code == 0 || !errors.Is(got.err, want) {
					t.Fatalf("cancellation cause lost: code=%d err=%v want=%v", got.code, got.err, want)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("command did not stop when its context ended")
			}
		})
	}
}

func TestOSRunnerBoundsInheritedPipesAndCleansControlChildren(t *testing.T) {
	for _, mode := range []string{"inherited", "closed", "cancel-tree", "overflow-inherited"} {
		t.Run(mode, func(t *testing.T) {
			executable, dir := commandProcessFixture(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			var child *os.Process
			received := false
			t.Cleanup(func() {
				cancel()
				if child != nil {
					_ = child.Kill()
					_, _ = child.Wait()
				}
				if !received {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("command wait did not finish after fixture cleanup")
					}
				}
			})
			go func() {
				_, _, code, err := runCmd(ctx, osRunner{}, executable, "-test.run=^TestHostdCommandProcessHelper$")
				done <- result{code, err}
			}()
			pid, err := strconv.Atoi(string(waitCommandFixture(t, filepath.Join(dir, "child-pid"))))
			if err != nil || pid <= 0 {
				t.Fatalf("invalid child pid: %d, %v", pid, err)
			}
			child, err = os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			waitCommandFixture(t, filepath.Join(dir, "ready"))
			if err := os.WriteFile(filepath.Join(dir, "release"), []byte("exit"), 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "cancel-tree" {
				cancel()
			}
			select {
			case got := <-done:
				received = true
				if (mode == "inherited" || mode == "overflow-inherited") && (got.code == 0 || !errors.Is(got.err, exec.ErrWaitDelay)) {
					t.Fatalf("inherited pipe was not reported as incomplete capture: code=%d err=%v", got.code, got.err)
				}
				if mode == "overflow-inherited" && (got.err == nil || !strings.Contains(got.err.Error(), "capture limit") || !strings.Contains(got.err.Error(), "command exit code 0")) {
					t.Fatalf("capture overflow replaced the exited parent's actual status: code=%d err=%v", got.code, got.err)
				}
				if mode == "closed" && (got.code != 0 || got.err != nil) {
					t.Fatalf("normal parent exit changed: %+v", got)
				}
				if mode == "cancel-tree" && (got.code == 0 || !errors.Is(got.err, context.Canceled)) {
					t.Fatalf("process tree cancellation cause lost: code=%d err=%v", got.code, got.err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("descendant kept the command wait blocked")
			}
			if runtime.GOOS == "linux" {
				limit := time.Now().Add(2 * time.Second)
				for {
					data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
					if os.IsNotExist(err) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					_, tail, found := strings.Cut(string(data), ") ")
					if found && strings.HasPrefix(tail, "Z ") {
						break
					}
					if time.Now().After(limit) {
						t.Fatal("control-command descendant is still running")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}
