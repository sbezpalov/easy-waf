// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package commandoutput

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestCaptureSharesTheExactBudgetAndDrainsOverflow(t *testing.T) {
	for _, size := range []int{0, 1024, Limit, Limit + 1, 2 * Limit} {
		var capture Capture
		n, err := io.Copy(capture.Stdout(), strings.NewReader(strings.Repeat("o", size)))
		if err != nil || n != int64(size) {
			t.Fatalf("stdout was not drained: copied=%d err=%v", n, err)
		}
		if size > Limit {
			if n, err := io.WriteString(capture.Stderr(), "later diagnostic"); n != len("later diagnostic") || err != nil {
				t.Fatalf("overflow stopped reading stderr: %d %v", n, err)
			}
		}
		out, stderr, err := capture.Result()
		if len(out) != min(size, Limit) || len(stderr) != 0 || !bytes.Equal(out, bytes.Repeat([]byte("o"), len(out))) {
			t.Fatalf("invalid captured prefix: stdout=%d stderr=%d input=%d", len(out), len(stderr), size)
		}
		if errors.Is(err, ErrLimit) != (size > Limit) {
			t.Fatalf("incomplete or exact-boundary output misreported: size=%d err=%v", size, err)
		}
	}
	var capture Capture
	if _, err := io.WriteString(capture.Stdout(), strings.Repeat("o", Limit-10)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(capture.Stderr(), strings.Repeat("e", 11)); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := capture.Result()
	if len(out)+len(stderr) != Limit || string(stderr) != strings.Repeat("e", 10) || !errors.Is(err, ErrLimit) {
		t.Fatalf("stdout/stderr did not share the budget: stdout=%d stderr=%d err=%v", len(out), len(stderr), err)
	}
}

func TestCaptureBoundsConcurrentWriters(t *testing.T) {
	var capture Capture
	var wg sync.WaitGroup
	for _, stream := range []io.Writer{capture.Stdout(), capture.Stderr()} {
		wg.Go(func() {
			chunk := bytes.Repeat([]byte("x"), 32<<10)
			for range 256 {
				if n, err := stream.Write(chunk); n != len(chunk) || err != nil {
					t.Errorf("capture stopped consuming output: %d %v", n, err)
					return
				}
			}
		})
	}
	wg.Wait()
	out, stderr, err := capture.Result()
	if len(out)+len(stderr) != Limit || !errors.Is(err, ErrLimit) {
		t.Fatalf("concurrent capture lost its shared limit: stdout=%d stderr=%d err=%v", len(out), len(stderr), err)
	}
}
