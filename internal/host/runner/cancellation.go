// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"errors"
	"net"
)

// DialContext bounds connection establishment only. Closing on cancellation
// also unblocks subsequent reads and writes, without a goroutine per request.
func closeOnCancel(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() { _ = conn.Close() })
}

// Preserve the transport error as well as the cancellation reason so callers
// can use errors.Is for context.Canceled and context.DeadlineExceeded.
func brokerIOError(ctx context.Context, err error) error {
	return errors.Join(err, ctx.Err())
}
