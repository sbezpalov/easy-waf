// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAptCommandBoundsInheritedPipes(t *testing.T) {
	for _, mode := range []string{"inherited", "closed", "cancel-tree"} {
		t.Run(mode, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			defer func() { _ = clearAptActionPID() }()
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
						t.Error("APT wait did not finish after fixture cleanup")
					}
				}
			})
			go func() {
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHostdCommandProcessHelper$")
				code, err := execAptCommand(ctx, cmd, func(string) error { return nil })
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
				if mode == "inherited" && (got.code == 0 || !errors.Is(got.err, exec.ErrWaitDelay)) {
					t.Fatalf("inherited output pipe: code=%d err=%v", got.code, got.err)
				}
				if mode == "closed" && (got.code != 0 || got.err != nil) {
					t.Fatalf("successful APT parent: code=%d err=%v", got.code, got.err)
				}
				if mode == "cancel-tree" && (got.code == 0 || !errors.Is(got.err, context.Canceled)) {
					t.Fatalf("cancellation cause lost: code=%d err=%v", got.code, got.err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("APT remained active after its parent exited")
			}
			if runtime.GOOS == "linux" {
				limit := time.Now().Add(2 * time.Second)
				for {
					data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
					_, tail, found := strings.Cut(string(data), ") ")
					dead := os.IsNotExist(err) || (found && strings.HasPrefix(tail, "Z "))
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					if mode == "closed" {
						if dead {
							t.Fatal("successful APT killed its service helper")
						}
						break
					}
					if dead {
						break
					}
					if time.Now().After(limit) {
						t.Fatal("failed APT left a descendant running")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestAptCommandPreservesDeadlineAndCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			defer func() { _ = clearAptActionPID() }()
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
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHostdCommandProcessHelper$")
				code, err := execAptCommand(ctx, cmd, func(string) error { return nil })
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
					t.Fatalf("APT cancellation result: code=%d err=%v want=%v", got.code, got.err, want)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("APT did not finish after its context ended")
			}
		})
	}
}

func TestAptCommandCapturesOutputAndDrainsOversizedLines(t *testing.T) {
	if stream := os.Getenv("EASY_WAF_APT_OUTPUT_CHILD"); stream != "" {
		output := io.Writer(os.Stdout)
		if stream == "stderr" {
			output = os.Stderr
		}
		switch stream {
		case "burst":
			for i := range 4096 {
				_, _ = fmt.Fprintf(os.Stdout, "stdout-%d\n", i)
				_, _ = fmt.Fprintf(os.Stderr, "stderr-%d\n", i)
			}
		case "normal", "failure":
			_, _ = fmt.Fprintln(os.Stdout, "stdout-line")
			_, _ = fmt.Fprintln(os.Stderr, "stderr-line")
		default:
			if _, err := fmt.Fprintln(output, strings.Repeat("x", 2<<20)); err != nil {
				os.Exit(90)
			}
		}
		if err := os.WriteFile(os.Getenv("EASY_WAF_APT_OUTPUT_MARKER"), []byte("finished"), 0o600); err != nil {
			os.Exit(91)
		}
		code, _ := strconv.Atoi(os.Getenv("EASY_WAF_APT_OUTPUT_EXIT"))
		os.Exit(code)
	}
	for _, stream := range []string{"normal", "failure", "burst", "stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			defer func() { _ = clearAptActionPID() }()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			fixtureDir := t.TempDir()
			marker := filepath.Join(fixtureDir, "finished")
			exit := "0"
			wantCode := 0
			captureFailure := stream == "stdout" || stream == "stderr"
			if captureFailure {
				wantCode = 1
			}
			if stream == "stderr" || stream == "failure" {
				exit, wantCode = "7", 7
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAptCommandCapturesOutputAndDrainsOversizedLines$")
			cmd.Env = append(os.Environ(), "EASY_WAF_APT_OUTPUT_CHILD="+stream, "EASY_WAF_APT_OUTPUT_MARKER="+marker, "EASY_WAF_APT_OUTPUT_EXIT="+exit)
			// Child TestMain may allocate temporary bookkeeping before os.Exit.
			// Keep those files inside the parent's automatically cleaned fixture.
			cmd.Env = append(cmd.Env, "TMPDIR="+fixtureDir, "TMP="+fixtureDir, "TEMP="+fixtureDir)
			var lines []string
			code, err := execAptCommand(ctx, cmd, func(line string) error { lines = append(lines, line); return nil })
			if _, markerErr := os.Stat(marker); markerErr != nil {
				t.Fatalf("child never finished writing output (pipe not drained): %v; command error=%v", markerErr, err)
			}
			if code != wantCode || (err != nil) != (wantCode != 0) {
				t.Fatalf("output error/apt exit status lost: code=%d error=%v", code, err)
			}
			if captureFailure && !strings.Contains(err.Error(), "apt output") {
				t.Fatalf("capture error hidden: %v", err)
			}
			if stream == "burst" {
				counts := make(map[string]int)
				for _, line := range lines {
					counts[line]++
				}
				if len(lines) != 8192 {
					t.Fatalf("buffered output truncated: got %d lines", len(lines))
				}
				for i := range 4096 {
					if counts[fmt.Sprintf("stdout-%d", i)] != 1 || counts[fmt.Sprintf("stderr-%d", i)] != 1 {
						t.Fatalf("buffered line %d missing or duplicated", i)
					}
				}
			} else if !captureFailure && (len(lines) != 2 || !strings.Contains(strings.Join(lines, "\n"), "stdout-line") || !strings.Contains(strings.Join(lines, "\n"), "stderr-line")) {
				t.Fatalf("normal stdout/stderr lost: %v", lines)
			}
			if ctx.Err() != nil {
				t.Fatalf("child required forced termination: %v", ctx.Err())
			}
		})
	}
}

func TestAptAttachAcceptsLinesPrimaryCanCapture(t *testing.T) {
	overrideAptActionLogForTest(t)
	line := strings.Repeat("x", 128<<10)
	if err := os.WriteFile(aptActionLogPath(), []byte(line+"\nnext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readAptActionLogFrom(0)
	if err != nil || len(lines) != 2 || lines[0] != line || lines[1] != "next" {
		t.Fatalf("attach rejected a valid primary log: lines=%d error=%v", len(lines), err)
	}
	if offset != int64(len(line)+len("\nnext\n")) {
		t.Fatalf("offset=%d", offset)
	}
}
