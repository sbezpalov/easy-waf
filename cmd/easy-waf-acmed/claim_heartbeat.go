// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"sync"
	"time"
)

func startClaimHeartbeat(ctx context.Context, interval, queryTimeout time.Duration, touch func(context.Context)) func() {
	done := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				select {
				case <-done:
					return
				default:
				}
				hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), queryTimeout)
				touch(hctx)
				cancel()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		// Touch publishes the new claim stamp only after its DB query settles.
		// Finalization must not race or abandon that in-flight publication.
		<-joined
	}
}
