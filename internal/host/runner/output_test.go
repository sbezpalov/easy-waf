// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
)

func TestLocalRunnerOutputHelper(_ *testing.T) {
	mode := os.Getenv("EASY_WAF_LOCAL_OUTPUT_TEST")
	if mode == "" {
		return
	}
	count := 256
	if mode == "small" {
		count = 1
	}
	for range count {
		if _, err := os.Stdout.WriteString(strings.Repeat("o", 32<<10)); err != nil {
			os.Exit(91)
		}
		if _, err := os.Stderr.WriteString(strings.Repeat("e", 32<<10)); err != nil {
			os.Exit(92)
		}
	}
	if err := os.WriteFile(os.Getenv("EASY_WAF_LOCAL_OUTPUT_MARKER"), []byte("drained"), 0o600); err != nil {
		os.Exit(93)
	}
	if mode == "overflow-wait" {
		time.Sleep(20 * time.Second)
	}
	code, _ := strconv.Atoi(os.Getenv("EASY_WAF_LOCAL_OUTPUT_EXIT"))
	os.Exit(code)
}

func TestLocalRunnerPreservesCancellationAndOutputLimitTogether(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "output-drained")
	t.Setenv("EASY_WAF_LOCAL_OUTPUT_TEST", "overflow-wait")
	t.Setenv("EASY_WAF_LOCAL_OUTPUT_MARKER", marker)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, 10*time.Second, executable, "-test.run=^TestLocalRunnerOutputHelper$")
		done <- err
	}()
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case cleanupErr := <-done:
				if cleanupErr != nil {
					t.Log("overflow fixture joined after cleanup cancellation")
				}
			case <-time.After(4 * time.Second):
				t.Error("overflow/cancellation fixture did not join")
			}
		}
	})
	waitLocalProcessFile(t, marker)
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, context.Canceled) || !errors.Is(err, commandoutput.ErrLimit) {
			t.Fatal("cancellation or output-limit cause was lost")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("output overflow prevented cancellation")
	}
}

func TestLocalRunnerBoundsOutputAndPreservesExitFailure(t *testing.T) {
	for _, code := range []int{0, 7} {
		for _, mode := range []string{"small", "overflow"} {
			t.Run(mode+"/"+strconv.Itoa(code), func(t *testing.T) {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(t.TempDir(), "output-drained")
				t.Setenv("EASY_WAF_LOCAL_OUTPUT_TEST", mode)
				t.Setenv("EASY_WAF_LOCAL_OUTPUT_MARKER", marker)
				t.Setenv("EASY_WAF_LOCAL_OUTPUT_EXIT", strconv.Itoa(code))
				out, err := Run(t.Context(), 10*time.Second, executable, "-test.run=^TestLocalRunnerOutputHelper$")
				if mode == "overflow" {
					if len(out) > 4<<20 || err == nil || !strings.Contains(err.Error(), "capture limit") {
						t.Errorf("local capture unbounded or reported success: stdout=%d error_present=%v", len(out), err != nil)
					}
				} else if string(out) != strings.Repeat("o", 32<<10) || (code == 0 && err != nil) {
					t.Error("normal command output/result changed")
				}
				if code != 0 {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
						t.Errorf("lost original nonzero exit: %v", err)
					}
				}
				if _, err := os.Stat(marker); err != nil {
					t.Errorf("capture stopped reading before helper finished: %v", err)
				}
			})
		}
	}
}
