// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

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

func TestLocalProcessHelper(_ *testing.T) {
	mode := os.Getenv("EASY_WAF_LOCAL_PROCESS_TEST")
	if mode == "" {
		return
	}
	dir := os.Getenv("EASY_WAF_LOCAL_PROCESS_DIR")
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			os.Exit(91)
		}
	}
	if mode == "child" {
		write("child-ready", "ready")
		time.Sleep(25 * time.Second)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(92)
	}
	child := exec.Command(executable, "-test.run=^TestLocalProcessHelper$")
	child.Env = append(os.Environ(), "EASY_WAF_LOCAL_PROCESS_TEST=child")
	if mode != "closed" {
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
	}
	if err := child.Start(); err != nil {
		os.Exit(93)
	}
	write("child-pid", strconv.Itoa(child.Process.Pid))
	limit := time.Now().Add(15 * time.Second)
	for time.Now().Before(limit) {
		if _, err := os.Stat(filepath.Join(dir, "child-ready")); err == nil {
			_, _ = fmt.Fprintln(os.Stdout, "parent output")
			_, _ = fmt.Fprintln(os.Stderr, "parent warning")
			write("ready", "ready")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for time.Now().Before(limit) {
		if mode == "cancel" {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			os.Exit(0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(94)
}

func waitLocalProcessFile(t *testing.T, path string) []byte {
	t.Helper()
	limit := time.Now().Add(6 * time.Second)
	for time.Now().Before(limit) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("local command fixture not ready: %s", filepath.Base(path))
	return nil
}

func TestLocalRunnerBoundsPipesAndCleansProcessGroup(t *testing.T) {
	for _, mode := range []string{"inherited", "closed", "cancel", "caller-deadline", "command-timeout"} {
		t.Run(mode, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			helperMode := mode
			if mode == "caller-deadline" || mode == "command-timeout" {
				helperMode = "cancel"
			}
			t.Setenv("EASY_WAF_LOCAL_PROCESS_TEST", helperMode)
			t.Setenv("EASY_WAF_LOCAL_PROCESS_DIR", dir)
			ctx, cancel := context.WithCancel(t.Context())
			budget := 12 * time.Second
			switch mode {
			case "caller-deadline":
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 3*time.Second)
			case "command-timeout":
				budget = 3 * time.Second
			}
			done := make(chan error, 1)
			go func() {
				_, err := Run(ctx, budget, executable, "-test.run=^TestLocalProcessHelper$")
				done <- err
			}()
			joined := false
			var child *os.Process
			t.Cleanup(func() {
				cancel()
				if child != nil {
					_ = child.Kill()
					_, _ = child.Wait()
				}
				if !joined {
					select {
					case cleanupErr := <-done:
						if cleanupErr != nil {
							t.Log("local fixture joined after cleanup cancellation")
						}
					case <-time.After(4 * time.Second):
						t.Error("local runner fixture did not join after cleanup")
					}
				}
			})
			pid, err := strconv.Atoi(string(waitLocalProcessFile(t, filepath.Join(dir, "child-pid"))))
			if err != nil || pid <= 0 {
				t.Fatalf("invalid owned child PID: %d %v", pid, err)
			}
			child, err = os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			waitLocalProcessFile(t, filepath.Join(dir, "ready"))
			if mode == "cancel" {
				cancel()
			} else if helperMode != "cancel" {
				if err := os.WriteFile(filepath.Join(dir, "release"), []byte("exit"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "caller-deadline" {
				<-ctx.Done()
			}
			waitBudget := 4 * time.Second
			if mode == "command-timeout" {
				waitBudget = 7 * time.Second
			}
			select {
			case err := <-done:
				joined = true
				if mode == "inherited" && !errors.Is(err, exec.ErrWaitDelay) {
					t.Fatalf("inherited pipe did not report capture failure: %v", err)
				}
				if mode == "closed" && err != nil {
					t.Fatalf("successful diagnostic parent changed: %v", err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("local cancellation cause lost: %v", err)
				}
				if (mode == "caller-deadline" || mode == "command-timeout") && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("local deadline cause lost: %v", err)
				}
			case <-time.After(waitBudget):
				t.Fatal("local runner retained request after parent exit/cancellation")
			}
			if runtime.GOOS == "linux" {
				limit := time.Now().Add(time.Second)
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
						t.Fatal("local diagnostic helper remained running")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestLocalRunnerPreservesStartAndPreCanceledFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-command")
	if out, err := Run(t.Context(), time.Second, missing); err == nil || len(out) != 0 {
		t.Fatal("missing command was not reported as a start failure")
	} else {
		var pathErr *os.PathError
		var execErr *exec.Error
		if !errors.As(err, &pathErr) && !errors.As(err, &execErr) {
			t.Fatalf("start error lost its original cause: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Run(ctx, time.Second, missing); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled command lost its context cause: %v", err)
	}
}
