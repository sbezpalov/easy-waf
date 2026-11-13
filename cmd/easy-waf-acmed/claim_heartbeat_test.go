// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestClaimHeartbeatStopJoinsInFlightTouch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	stamp, updated := time.Time{}, time.Now()
	stop := startClaimHeartbeat(ctx, time.Millisecond, time.Second, func(context.Context) {
		close(entered)
		<-release
		stamp = updated // The store updates the shared claim stamp after its query.
		close(finished)
	})
	stopped := make(chan struct{})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("heartbeat callback did not finish")
		}
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Error("heartbeat stop did not join")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not start")
	}
	cancel() // A lifecycle cancellation must not abandon the in-flight write.
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop returned while the claim stamp could still change")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not wait for the completed heartbeat")
	}
	if stamp != updated {
		t.Fatal("finalization observed the old claim stamp")
	}
}

func TestClaimHeartbeatIdleAndCanceledStopIsConcurrentAndIdempotent(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "canceled"}[canceled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stop := startClaimHeartbeat(ctx, time.Hour, time.Second, func(context.Context) {
				t.Error("idle/canceled heartbeat invoked the store")
			})
			if canceled {
				cancel()
			}
			var callers sync.WaitGroup
			for range 16 {
				callers.Go(stop)
			}
			joined := make(chan struct{})
			go func() { callers.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Fatal("idle heartbeat stop waited for another tick or deadlocked")
			}
			stop()
		})
	}
}

func TestClaimHeartbeatKeepsValuesAndSettlesQueryBeforeStop(t *testing.T) {
	type claimKey struct{}
	parent, cancel := context.WithTimeout(context.WithValue(t.Context(), claimKey{}, "claim"), 5*time.Second)
	defer cancel()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var once sync.Once
	stop := startClaimHeartbeat(parent, time.Millisecond, 30*time.Second, func(hctx context.Context) {
		entered <- hctx
		<-release
	})
	t.Cleanup(func() { once.Do(func() { close(release) }); stop() })
	var hctx context.Context
	select {
	case hctx = <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not run")
	}
	cancel()
	if hctx.Err() != nil || hctx.Value(claimKey{}) != "claim" {
		t.Fatal("heartbeat inherited lifecycle cancellation or lost claim metadata")
	}
	deadline, ok := hctx.Deadline()
	parentDeadline, _ := parent.Deadline()
	if !ok || !deadline.After(parentDeadline) || time.Until(deadline) > 30*time.Second {
		t.Fatal("heartbeat did not retain its fresh bounded query budget")
	}
	once.Do(func() { close(release) })
	stop()
	select {
	case <-hctx.Done():
	default:
		t.Fatal("completed heartbeat retained its query context/timer")
	}
}

func TestClaimHeartbeatQueryTimeoutIsJoined(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	cause := make(chan error, 1)
	stop := startClaimHeartbeat(ctx, time.Millisecond, 30*time.Millisecond, func(hctx context.Context) {
		close(entered)
		<-hctx.Done()
		cause <- hctx.Err()
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not run")
	}
	cancel()
	stop()
	if err := <-cause; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("in-flight query was abandoned rather than settled: %v", err)
	}
}
