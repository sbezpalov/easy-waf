// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func aptStatusRunID(t *testing.T) string {
	t.Helper()
	var status struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(dispatchAptActionStatus().Stdout), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.RunID) != 32 || strings.Trim(status.RunID, "0123456789abcdef") != "" {
		t.Fatalf("invalid observation ID in status: %q", status.RunID)
	}
	return status.RunID
}

func TestAptObservationAfterCompletionDoesNotStartAnotherMutation(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		name := "stream"
		if synchronous {
			name = "synchronous"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			t.Cleanup(resetAptUpgradeState)
			var id string
			calls := 0
			execute := func(_ context.Context, emit func(string) error) (int, error) {
				calls++
				id = aptStatusRunID(t) // status observed before the selected run finishes
				_ = emit("original package result")
				return 7, nil
			}
			if synchronous {
				d := Dispatcher{Runner: &aptMutationRunner{run: func(ctx context.Context, _ string, _ []string, emit func(string) error) (int, error) {
					return execute(ctx, emit)
				}}}
				_ = d.Dispatch(t.Context(), []string{"apt-clean"})
			} else {
				SetAptUpgradeStreamHookForTest(execute)
				dispatchAptStream(io.Discard, "upgrade")
			}
			// Reaching the observer after completion must drain the original result,
			// not turn the stale "active" response into a fresh upgrade request.
			SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) { calls++; return 0, nil })
			var output bytes.Buffer
			dispatchAptObserveStream(&output, id)
			events := readStreamEvents(t, &output)
			last := events[len(events)-1]
			if last.Type != "exit" || last.Code != 7 || !slices.ContainsFunc(events, func(e streamEvent) bool { return e.Data == "original package result" }) || calls != 1 {
				t.Fatalf("observation started/replaced a completed operation: calls=%d events=%+v", calls, events)
			}
			if got := aptStatusRunID(t); got != id {
				t.Fatalf("observation changed run identity: %s -> %s", id, got)
			}
		})
	}
}

func TestAptObservationRejectsAbsentReplacedAndMalformedIDs(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	t.Cleanup(resetAptUpgradeState)
	if err := os.WriteFile(aptActionLogPath(), []byte("saved output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) { calls++; return 0, nil })
	assertRejected := func(id string) {
		t.Helper()
		before, err := os.ReadFile(aptActionLogPath())
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		dispatchAptObserveStream(&output, id)
		events := readStreamEvents(t, &output)
		if len(events) != 1 || events[0].Type != "exit" || events[0].Code != -1 || events[0].Error == "" || calls != 0 {
			t.Fatalf("invalid observation started an operation: calls=%d events=%+v", calls, events)
		}
		after, err := os.ReadFile(aptActionLogPath())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("observation replaced saved output: %q %v", after, err)
		}
	}
	assertRejected(strings.Repeat("a", 32))
	if aptActionCurrent != nil {
		t.Fatal("absent observation reserved a new action")
	}
	first, started, err := acquireAptAction("upgrade", aptStreaming)
	if err != nil || !started {
		t.Fatalf("reserve first: %v %v", started, err)
	}
	finishAptAction(first, 7, "")
	releaseAptAction(first)
	second, started, err := acquireAptAction("clean", aptSynchronous)
	if err != nil || !started {
		t.Fatalf("reserve next: %v %v", started, err)
	}
	defer releaseAptAction(second)
	if first.id == second.id {
		t.Fatal("replacement reused observation identity")
	}
	// An unverifiable PID file must not be cleared by a stale observer.
	if err := storeAptActionPID([]byte("fixture bookkeeping\n")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.id, "", "a", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), "../upgrade"} {
		assertRejected(id)
	}
	if active, _, _ := aptActionSnapshot(); !active || aptStatusRunID(t) != second.id {
		t.Fatal("stale observer released/replaced the current reservation")
	}
	if data, err := os.ReadFile(aptActionPIDPath()); err != nil || string(data) != "fixture bookkeeping\n" {
		t.Fatalf("observer altered PID bookkeeping: %q %v", data, err)
	}
}

func TestSocketRoundTripAptObservationOnly(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	t.Cleanup(resetAptUpgradeState)
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		_ = emit("original socket result")
		return 7, nil
	})
	dispatchAptStream(io.Discard, "upgrade")
	id := aptStatusRunID(t)
	SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) {
		t.Error("observer invoked the package executor")
		return 0, nil
	})
	// Real unix connections exercise server opcode/framing without starting
	// the appliance listener. TestMain bypasses peer checks for test users.
	ln, err := net.Listen("unix", shortTempSock(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, args := range [][]string{
		{"apt-action-attach-stream", id},
		{"apt-action-attach-stream"},
		{"apt-action-attach-stream", id, "upgrade"},
		{"apt-action-attach-stream", strings.Repeat("b", 32)},
	} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := ln.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			handleConn(t.Context(), c, &Dispatcher{Runner: &aptMutationRunner{}})
		}()
		conn, err := net.Dial("unix", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := json.NewEncoder(conn).Encode(Request{Argv: args}); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		events := readSocketStreamEvents(t, conn)
		_ = conn.Close()
		<-done
		if len(events) == 0 {
			t.Fatalf("no response for %v", args)
		}
		last := events[len(events)-1]
		want := -1
		if len(args) == 2 && args[1] == id {
			want = 7
		}
		if last.Type != "exit" || last.Code != want || (want == -1 && last.Error == "") {
			t.Fatalf("wrong observation response for %v: %+v", args, events)
		}
	}
}
