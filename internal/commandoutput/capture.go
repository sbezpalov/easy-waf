// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package commandoutput bounds retained subprocess output while draining pipes.
package commandoutput

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

const Limit = 4 << 20

var ErrLimit = errors.New("command output capture limit exceeded")

// Capture's zero value is ready to use. Stdout and Stderr share one byte budget;
// their process-copy goroutines may write concurrently. Excess bytes are drained,
// never returned as short writes that could stop a child halfway through work.
type Capture struct {
	mu       sync.Mutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	used     int
	exceeded bool
}

func (c *Capture) Stdout() io.Writer { return outputWriter{c: c} }

func (c *Capture) Stderr() io.Writer { return outputWriter{c: c, stderr: true} }

// Result returns owned-buffer views and any capture failure after the caller
// has joined both process-copy goroutines. Do not write after reading Result.
func (c *Capture) Result() (stdout, stderr []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exceeded {
		err = fmt.Errorf("%w (%d bytes across stdout/stderr)", ErrLimit, Limit)
	}
	return c.stdout.Bytes(), c.stderr.Bytes(), err
}

type outputWriter struct {
	c      *Capture
	stderr bool
}

func (w outputWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	n := min(len(p), Limit-w.c.used)
	if n > 0 {
		dst := &w.c.stdout
		if w.stderr {
			dst = &w.c.stderr
		}
		_, _ = dst.Write(p[:n]) // bytes.Buffer.Write always succeeds.
		w.c.used += n
	}
	w.c.exceeded = w.c.exceeded || n < len(p)
	return len(p), nil
}
