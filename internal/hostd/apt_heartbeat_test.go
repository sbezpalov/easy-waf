// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAptHeartbeatDiscardsQueuedTickAfterStop(t *testing.T) {
	for _, stopContext := range []bool{true, false} {
		name := "done"
		if stopContext {
			name = "context"
		}
		t.Run(name, func(t *testing.T) {
			previousInterval := aptActionHeartbeatInterval()
			setAptActionHeartbeatIntervalForTest(time.Millisecond)
			defer setAptActionHeartbeatIntervalForTest(previousInterval)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan struct{})
			stopped := make(chan struct{})
			var emitMu sync.Mutex
			var calls atomic.Int32
			lastLineAt := time.Now().Add(-time.Minute)
			emitMu.Lock()
			go func() {
				defer close(stopped)
				aptActionHeartbeat(ctx, done, time.Now(), &emitMu, &lastLineAt, func(string) error {
					calls.Add(1)
					return nil
				})
			}()
			// Leave the first tick queued behind a simulated output callback.
			time.Sleep(30 * time.Millisecond)
			if stopContext {
				cancel()
			} else {
				close(done)
			}
			emitMu.Unlock()
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				t.Fatal("heartbeat did not stop after releasing the output callback")
			}
			if calls.Load() != 0 {
				t.Fatal("queued heartbeat emitted after stop")
			}
		})
	}
}

// The heartbeat is held inside emit while the command either emits or returns.
// These tests verify ownership without relying on a race detector or real APT.
func TestAptHeartbeatCallbackOwnership(t *testing.T) {
	for _, commandOutput := range []bool{true, false} {
		name := "join_before_return"
		if commandOutput {
			name = "serialize_output"
		}
		t.Run(name, func(t *testing.T) {
			previousInterval := aptActionHeartbeatInterval()
			previousHook := aptActionStreamHook
			setAptActionHeartbeatIntervalForTest(10 * time.Millisecond)
			heartbeatEntered := make(chan struct{})
			releaseHeartbeat := make(chan struct{})
			commandReady := make(chan struct{})
			commandEntered := make(chan struct{}, 1)
			var active atomic.Int32
			var overlap atomic.Bool
			var heartbeatCalls atomic.Int32
			wantErr := errors.New("fixture apt exit")
			ctx, cancel := context.WithCancel(t.Context())
			aptActionStreamHook = func(ctx context.Context, _ string, emit func(string) error) (int, error) {
				select {
				case <-heartbeatEntered:
				case <-ctx.Done():
					return 1, ctx.Err()
				}
				close(commandReady)
				if commandOutput {
					_ = emit("command output")
				}
				return 7, wantErr
			}
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			received := false
			t.Cleanup(func() {
				cancel()
				select {
				case <-releaseHeartbeat:
				default:
					close(releaseHeartbeat)
				}
				if !received {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("APT fixture did not finish after releasing heartbeat")
					}
				}
				aptActionStreamHook = previousHook
				setAptActionHeartbeatIntervalForTest(previousInterval)
			})
			go func() {
				code, err := runAptActionStream(ctx, "upgrade", func(line string) error {
					if active.Add(1) != 1 {
						overlap.Store(true)
					}
					defer active.Add(-1)
					if strings.Contains(line, "still working") {
						if heartbeatCalls.Add(1) == 1 {
							close(heartbeatEntered)
							<-releaseHeartbeat
						}
					} else {
						commandEntered <- struct{}{}
					}
					return nil
				})
				done <- result{code, err}
			}()
			select {
			case <-commandReady:
			case <-time.After(3 * time.Second):
				t.Fatal("heartbeat never entered its callback")
			}
			select {
			case <-commandEntered:
				t.Error("command output overlapped the heartbeat callback")
			case <-done:
				received = true
				t.Error("APT returned while its heartbeat callback was still active")
			case <-time.After(100 * time.Millisecond):
			}
			close(releaseHeartbeat)
			if !received {
				select {
				case got := <-done:
					received = true
					if got.code != 7 || !errors.Is(got.err, wantErr) {
						t.Errorf("command result changed: code=%d err=%v", got.code, got.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("APT did not stop after callback release")
				}
			}
			if overlap.Load() || active.Load() != 0 {
				t.Errorf("callback ownership: overlap=%v active=%d", overlap.Load(), active.Load())
			}
		})
	}
}
