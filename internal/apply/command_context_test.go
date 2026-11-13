// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("EASY_WAF_APPLY_COMMAND_TEST") == "fail" {
		os.Exit(23)
	}
	if os.Getenv("EASY_WAF_APPLY_COMMAND_TEST") == "1" {
		if err := os.WriteFile(os.Getenv("EASY_WAF_APPLY_COMMAND_READY"), []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
		// A broken implementation exits on its own rather than leaking a child.
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestValidationPreservesProcessFailure(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_APPLY_COMMAND_TEST", "fail")
	err = Validate(t.Context(), self, "fixture.cfg")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatalf("lost process exit status: %v", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ordinary command failure misreported as cancellation: %v", err)
	}
}

func TestApplyCommandsHonorContextWhileRunning(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"validate", "reload"} {
		for _, deadline := range []bool{false, true} {
			name := command + "/cancel"
			if deadline {
				name = command + "/deadline"
			}
			t.Run(name, func(t *testing.T) {
				ready := filepath.Join(t.TempDir(), "ready")
				t.Setenv("EASY_WAF_APPLY_COMMAND_TEST", "1")
				t.Setenv("EASY_WAF_APPLY_COMMAND_READY", ready)
				if command == "reload" {
					installTestSystemctl(t, self)
				}
				ctx, cancel := context.WithCancel(t.Context())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(t.Context(), 3*time.Second)
				}
				defer cancel()
				result := make(chan error, 1)
				go func() {
					if command == "reload" {
						result <- ReloadHAProxy(ctx)
					} else {
						result <- Validate(ctx, self, "fixture.cfg")
					}
				}()
				startupDeadline := time.Now().Add(4 * time.Second)
				for {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					if time.Now().After(startupDeadline) {
						t.Fatal("command fixture did not start")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !deadline {
					cancel()
				}
				<-ctx.Done()
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("command error = %v, want %v", err, want)
					}
				case <-time.After(2 * time.Second):
					err := <-result
					t.Fatalf("command remained blocked until fixture exit: %v", err)
				}
			})
		}
	}
}

func installTestSystemctl(t *testing.T, self string) {
	t.Helper()
	dir := t.TempDir()
	name := "systemctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	program, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	// Execute a private copy of this test binary instead of the host's systemctl.
	if err := os.WriteFile(filepath.Join(dir, name), program, 0o700); err != nil { // #nosec G306 -- owner-only executable fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
