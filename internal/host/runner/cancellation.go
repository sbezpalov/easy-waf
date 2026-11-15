// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// DialContext bounds connection establishment only. Closing on cancellation
// also unblocks subsequent reads and writes, without a goroutine per request.
func closeOnCancel(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() { _ = conn.Close() })
}

// Preserve the transport error as well as the cancellation reason so callers
// can use errors.Is for context.Canceled and context.DeadlineExceeded.
func brokerIOError(ctx context.Context, err error) error {
	return brokerIOErrorAt(ctx, err, time.Now())
}

// A conn.SetDeadline copied from the context can fire before ctx.Err is
// visible. That read is still the context deadline, not a separate timeout.
func brokerIOErrorAt(ctx context.Context, err error, now time.Time) error {
	if err == nil {
		return nil
	}
	ctxErr := ctx.Err()
	if ctxErr == nil && errors.Is(err, os.ErrDeadlineExceeded) {
		if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
			ctxErr = context.DeadlineExceeded
		}
	}
	if ctxErr == nil {
		return err
	}
	return errors.Join(err, ctxErr)
}
