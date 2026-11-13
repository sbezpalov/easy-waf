// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOSRunnerBoundsCommandOutputWithoutBreakingTheChild(t *testing.T) {
	for _, code := range []int{0, 7} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			executable, dir := commandProcessFixture(t, "capture-overflow")
			t.Setenv("EASY_WAF_EXEC_TEST_EXIT", strconv.Itoa(code))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			out, stderr, got, err := runCmd(ctx, osRunner{}, executable, "-test.run=^TestHostdCommandProcessHelper$")
			if len(out)+len(stderr) > 4<<20 || got == 0 || err == nil || !strings.Contains(err.Error(), "capture limit") {
				t.Errorf("unbounded or apparently successful capture: stdout=%d stderr=%d code=%d err=%v", len(out), len(stderr), got, err)
			}
			if code != 0 && got != code {
				t.Errorf("lost real command exit code: got=%d want=%d", got, code)
			}
			if code == 0 && (got != 1 || err == nil || !strings.Contains(err.Error(), "command exit code 0")) {
				t.Errorf("incomplete capture did not retain the successful child's actual exit: code=%d", got)
			}
			if _, err := os.Stat(filepath.Join(dir, "output-drained")); err != nil {
				t.Fatalf("capture limit broke child output instead of draining it: %v", err)
			}
		})
	}
}

func TestOSRunnerKeepsCancellationAfterOutputOverflow(t *testing.T) {
	executable, dir := commandProcessFixture(t, "capture-overflow")
	t.Setenv("EASY_WAF_EXEC_TEST_WAIT", "1")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		bytes int
		code  int
		err   error
	}
	done := make(chan result, 1)
	go func() {
		out, stderr, code, err := runCmd(ctx, osRunner{}, executable, "-test.run=^TestHostdCommandProcessHelper$")
		done <- result{len(out) + len(stderr), code, err}
	}()
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("overflow fixture did not join after cancellation")
			}
		}
	})
	waitCommandFixture(t, filepath.Join(dir, "output-drained"))
	cancel()
	select {
	case got := <-done:
		joined = true
		if got.bytes > 4<<20 || got.code == 0 || !errors.Is(got.err, context.Canceled) || !strings.Contains(got.err.Error(), "capture limit") {
			t.Fatalf("capture overflow lost cancellation or resource bound: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("overflow fixture did not stop on cancellation")
	}
}
