// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type aptBlockedWriter struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	match   string
}

func (w *aptBlockedWriter) Write(p []byte) (int, error) {
	var e streamEvent
	if json.Unmarshal(bytes.TrimSpace(p), &e) == nil && (w.match == "" || e.Data == w.match) {
		w.once.Do(func() { close(w.entered); <-w.release })
	}
	return w.Buffer.Write(p)
}

func (w *aptBlockedWriter) unblock() {
	select {
	case <-w.release:
	default:
		close(w.release)
	}
}

func waitAptCompletion(t *testing.T, code int, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if active, got, errMsg := aptActionSnapshot(); !active {
			if got != code || errMsg != message {
				t.Fatalf("client affected command result: code=%d error=%q", got, errMsg)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("blocked client prevented APT execution/completion")
}

func TestAptCommandCompletesWhileClientWriteIsBlocked(t *testing.T) {
	for _, firstWrite := range []bool{true, false} {
		name, match := "output", "fixture output"
		if firstWrite {
			name, match = "start", ""
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			writer := &aptBlockedWriter{entered: make(chan struct{}), release: make(chan struct{}), match: match}
			done := make(chan struct{})
			wantErr := errors.New("fixture package error")
			SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
				if !firstWrite {
					_ = emit("fixture output")
				}
				select {
				case <-writer.entered:
				case <-ctx.Done():
					return 1, ctx.Err()
				}
				_ = emit("final package output")
				return 7, wantErr
			})
			t.Cleanup(func() {
				writer.unblock()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("blocked-client fixture did not finish after releasing writer")
				}
				resetAptUpgradeState()
			})
			go func() { defer close(done); dispatchAptStream(writer, "upgrade") }()
			select {
			case <-writer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("client writer did not block")
			}
			waitAptCompletion(t, 7, wantErr.Error())
			if log := dispatchAptActionLog(); !strings.Contains(log.Stdout, "final package output") {
				t.Fatal("command completion lost its durable final output")
			}
			writer.unblock()
			<-done
			events := readStreamEvents(t, &writer.Buffer)
			last := events[len(events)-1]
			if last.Type != "exit" || last.Code != 7 || last.Error != wantErr.Error() || events[len(events)-2].Data != "final package output" {
				t.Fatalf("healthy final drain lost output/result: %+v", events)
			}
		})
	}
}

func TestAptTrackedChildDrainsBothPipesBehindBlockedClient(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	executable, _ := commandProcessFixture(t, "burst")
	writer := &aptBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		select {
		case <-writer.entered:
		case <-ctx.Done():
			return 1, ctx.Err()
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return (osRunner{}).RunApt(ctx, executable, []string{"-test.run=^TestHostdCommandProcessHelper$"}, emit)
	})
	t.Cleanup(func() {
		writer.unblock()
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Error("tracked child fixture did not finish")
		}
		resetAptUpgradeState()
	})
	go func() { defer close(done); dispatchAptStream(writer, "upgrade") }()
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not block")
	}
	waitAptCompletion(t, 0, "")
	log := dispatchAptActionLog()
	if strings.Count(log.Stdout, "fixture stdout ") != 128 || strings.Count(log.Stdout, "fixture stderr ") != 128 {
		t.Fatal("blocked socket prevented real child pipe draining")
	}
	writer.unblock()
	<-done
	events := readStreamEvents(t, &writer.Buffer)
	last := events[len(events)-1]
	if len(events) != 258 || last.Type != "exit" || last.Code != 0 || last.Error != "" {
		t.Fatalf("bounded healthy backlog lost child output/completion: lines=%d exit=%+v", len(events), last)
	}
}

func TestAptLiveQueueBoundsCountAndBytesAndReportsOverflow(t *testing.T) {
	for _, large := range []bool{false, true} {
		name, line, count := "line_count", "package output", maxAptLiveLines+1
		if large {
			name, line, count = "bytes", strings.Repeat("x", maxAptOutputLineBytes-1), 5
		}
		t.Run(name, func(t *testing.T) {
			writer := &aptBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
			delivery := newAptLiveDelivery(newAptStreamConn(writer))
			finished := false
			t.Cleanup(func() {
				writer.unblock()
				if !finished {
					delivery.finish(0, "")
				}
			})
			_ = delivery.line("first")
			select {
			case <-writer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("delivery did not block")
			}
			for range count {
				if err := delivery.line(line); err != nil {
					t.Fatal("live delivery failure reached package callback")
				}
			}
			if !errors.Is(delivery.failure(), errAptLiveBackpressure) {
				t.Fatal("queue overflow was hidden")
			}
			delivery.mu.Lock()
			queuedBytes, queuedLines := delivery.bytes, len(delivery.pending)
			delivery.mu.Unlock()
			if queuedBytes > maxAptLiveBytes || queuedLines > maxAptLiveLines || (large && queuedBytes != maxAptLiveBytes) || (!large && queuedLines != maxAptLiveLines) {
				t.Fatalf("unbounded/unexpected queue: bytes=%d lines=%d", queuedBytes, queuedLines)
			}
			writer.unblock()
			delivery.finish(0, "")
			finished = true
			events := readStreamEvents(t, &writer.Buffer)
			last := events[len(events)-1]
			if last.Type != "exit" || last.Code != -1 || !strings.Contains(last.Error, "saved package log") {
				t.Fatalf("incomplete live output reported successful completion: %+v", last)
			}
			if delivery.bytes != 0 || len(delivery.pending) != 0 {
				t.Fatal("failed subscriber retained queued text")
			}
		})
	}
}

func TestAptLiveOverflowPreservesFullLogAndActualCommandResult(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	writer := &aptBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		select {
		case <-writer.entered:
		case <-ctx.Done():
			return 1, ctx.Err()
		}
		for range maxAptLiveLines + 1 {
			_ = emit("regular package line")
		}
		_ = emit("final package output")
		return 0, nil
	})
	t.Cleanup(func() {
		writer.unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("overflow fixture did not finish")
		}
		resetAptUpgradeState()
	})
	go func() { defer close(done); dispatchAptStream(writer, "upgrade") }()
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("live subscriber did not block")
	}
	waitAptCompletion(t, 0, "")
	log := dispatchAptActionLog()
	if strings.Count(log.Stdout, "regular package line\n") != maxAptLiveLines+1 || !strings.HasSuffix(log.Stdout, "final package output\n") {
		t.Fatal("client backpressure truncated or failed durable package output")
	}
	writer.unblock()
	<-done
	events := readStreamEvents(t, &writer.Buffer)
	last := events[len(events)-1]
	if last.Code != -1 || last.Error != errAptLiveBackpressure.Error() {
		t.Fatalf("stream substituted command success for delivery failure: %+v", last)
	}
}

type aptDeadlineProbe struct {
	net.Conn
	requested chan time.Time
	closed    chan struct{}
	once      sync.Once
}

func (c *aptDeadlineProbe) Close() error {
	err := c.Conn.Close()
	if c.closed != nil {
		c.once.Do(func() { close(c.closed) })
	}
	return err
}

func (c *aptDeadlineProbe) SetWriteDeadline(deadline time.Time) error {
	c.requested <- deadline
	// Verify the real requested production budget while keeping a blocked
	// net.Pipe test quick. Lifetime-clamped deadlines remain earlier.
	if quick := time.Now().Add(25 * time.Millisecond); deadline.After(quick) {
		deadline = quick
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestAptSocketWritesHavePerWriteAndTotalDeadlines(t *testing.T) {
	for _, lifetime := range []bool{false, true} {
		name := "per_write"
		if lifetime {
			name = "total_lifetime"
		}
		t.Run(name, func(t *testing.T) {
			peer, socket := net.Pipe()
			defer peer.Close()
			defer socket.Close()
			probe := &aptDeadlineProbe{Conn: socket, requested: make(chan time.Time, 1)}
			sc := newAptStreamConn(probe)
			if lifetime {
				sc.expires = time.Now().Add(time.Second)
			}
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- sc.writeEvent(streamEvent{Type: "line", Data: "unread"}) }()
			select {
			case err := <-done:
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("unread socket did not time out: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("socket write ignored its deadline")
			}
			deadline := <-probe.requested
			if lifetime {
				if !deadline.Equal(sc.expires) {
					t.Fatal("write deadline extended the overall stream lifetime")
				}
			} else if budget := deadline.Sub(start); budget < aptStreamWriteTimeout || budget > aptStreamWriteTimeout+time.Second {
				t.Fatalf("unexpected production write budget: %s", budget)
			}
		})
	}
}

func TestAptDeliveryClosesTimedOutSocketWithoutChangingCommandResult(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	peer, socket := net.Pipe()
	defer peer.Close()
	defer socket.Close()
	probe := &aptDeadlineProbe{Conn: socket, requested: make(chan time.Time, 4), closed: make(chan struct{})}
	release := make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("package completed despite unread socket")
		select {
		case <-release:
		case <-ctx.Done():
			return 1, ctx.Err()
		}
		return 7, nil
	})
	done := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = socket.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("timed-out socket fixture did not finish")
		}
		resetAptUpgradeState()
	})
	go func() { defer close(done); dispatchAptStream(probe, "upgrade") }()
	select {
	case <-probe.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("failed socket stayed open until package completion")
	}
	if active, _, _ := aptActionSnapshot(); !active {
		t.Fatal("timed-out subscriber canceled or released the active command")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed-out subscriber kept its delivery goroutine")
	}
	waitAptCompletion(t, 7, "")
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed delivery did not close its connection: %v", err)
	}
}

type aptFailingFollower struct {
	calls int
}

func (w *aptFailingFollower) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, errors.New("fixture client disconnected")
	}
	return len(p), nil
}

func TestAptFollowerReleasesFailedClientWhileCommandStaysActive(t *testing.T) {
	for _, idle := range []bool{false, true} {
		name := "saved_output"
		if idle {
			name = "idle_heartbeat"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			interval := aptActionHeartbeatInterval()
			setAptActionHeartbeatIntervalForTest(10 * time.Millisecond)
			record, started, err := acquireAptAction("upgrade", aptStreaming)
			if err != nil || !started {
				t.Fatalf("reserve: %v %v", started, err)
			}
			done := make(chan struct{})
			launched := false
			t.Cleanup(func() {
				finishAptAction(record, 0, "")
				if launched {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("follower fixture did not finish")
					}
				}
				releaseAptAction(record)
				resetAptUpgradeState()
				setAptActionHeartbeatIntervalForTest(interval)
			})
			file, err := createAptActionLog(aptActionLogPath())
			if err != nil {
				t.Fatal(err)
			}
			if !idle {
				_, _ = file.WriteString("saved output\n")
			}
			_ = file.Close()
			publishAptActionLog(record, nil)
			writer := &aptFailingFollower{}
			launched = true
			go func() { defer close(done); dispatchAptObserveStream(writer, record.id) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("failed follower waited for package completion")
			}
			if active, _, _ := aptActionSnapshot(); !active || record.refs != 2 || writer.calls != 2 {
				t.Fatalf("follower leaked its reference or canceled the action: active=%v refs=%d writes=%d", active, record.refs, writer.calls)
			}
			if log := dispatchAptActionLog(); idle && log.Stdout != "" {
				t.Fatal("observer heartbeat changed the durable package log")
			}
		})
	}
}
