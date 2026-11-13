// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type advisoryLockAcquire func(context.Context, int64) (func() error, error)

type applicationMutationKey struct{}

type applicationMutationLease struct {
	engine   *Engine
	released chan struct{}
}

// LockApplicationMutation serializes application preimage reads, row/token
// writes, apply and compensation with other mutations and edge operations.
// Use the returned context with this Engine and call release when it ends.
// Lock acquisition has a two-minute maximum; the returned context retains the
// caller's original cancellation and deadline rather than that wait budget.
func (e *Engine) LockApplicationMutation(ctx context.Context) (context.Context, func() error, error) {
	return e.lockApplicationMutation(ctx, func(ctx context.Context, key int64) (func() error, error) {
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return e.Store.AcquireAdvisoryLock(waitCtx, key)
	})
}

func (e *Engine) lockApplicationMutation(ctx context.Context, acquire advisoryLockAcquire) (context.Context, func() error, error) {
	if lease, ok := ctx.Value(applicationMutationKey{}).(*applicationMutationLease); ok && lease.engine == e {
		select {
		case <-lease.released:
		default:
			return ctx, func() error { return nil }, nil
		}
	}
	release, err := acquire(ctx, ApplyOrUndoAdvisoryLockKey)
	if err != nil {
		return nil, nil, fmt.Errorf("acquire application mutation lock: %w", err)
	}
	lease := &applicationMutationLease{engine: e, released: make(chan struct{})}
	var once sync.Once
	var releaseErr error
	return context.WithValue(ctx, applicationMutationKey{}, lease), func() error {
		once.Do(func() {
			close(lease.released)
			releaseErr = release()
		})
		return releaseErr
	}, nil
}
