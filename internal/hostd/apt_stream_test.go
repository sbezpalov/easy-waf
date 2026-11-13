// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shortTempSock(t *testing.T) string {
	t.Helper()
	// Some Windows temp roots contain characters AF_UNIX rejects. Keep the
	// already length-sensitive socket below the package's short workspace path.
	dir, err := os.MkdirTemp(".", ".sock-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func resetAptUpgradeState() {
	ResetAptUpgradeStateForTest()
}

func overrideAptActionLogForTest(t *testing.T) {
	t.Helper()
	previous := aptActionLogPathOverride
	SetAptActionLogPathOverrideForTest(filepath.Join(t.TempDir(), "apt-action.log"))
	t.Cleanup(func() { SetAptActionLogPathOverrideForTest(previous) })
}

func readStreamEvents(t *testing.T, r io.Reader) []streamEvent {
	t.Helper()
	var out []streamEvent
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var ev streamEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("json: %v line %q", err, sc.Text())
		}
		out = append(out, ev)
	}
	return out
}

func TestAptStatusCannotReleaseLocalSingleFlightBeforePIDExists(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	started, err := aptActionTryStart()
	if err != nil || !started {
		t.Fatalf("start: %v, %v", started, err)
	}
	if active, _, _ := aptActionSnapshot(); !active {
		t.Error("status cleared the reservation before the child PID was persisted")
	}
	if started, err := aptActionTryStart(); err != nil || started {
		t.Fatalf("status allowed a second primary: %v, %v", started, err)
	}
	aptActionFinish(2, "apt failed")
	if active, code, message := aptActionSnapshot(); active || code != 2 || message != "apt failed" {
		t.Fatalf("finished result lost: active=%v code=%d error=%q", active, code, message)
	}
}

func TestAptStatusCannotInventSuccessForRecoveredDeadPID(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	// An invalid/non-live PID models stale bookkeeping after a broker restart.
	if err := storeAptActionPID([]byte("0\n")); err != nil {
		t.Fatal(err)
	}
	if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
		t.Fatalf("unknown result reported as success: active=%v code=%d error=%q", active, code, message)
	}
	if started, err := aptActionTryStart(); err != nil || !started {
		t.Fatalf("stale PID blocked a new operation: %v, %v", started, err)
	}
	aptActionFinish(0, "")
	if active, code, message := aptActionSnapshot(); active || code != 0 || message != "" {
		t.Fatalf("new operation result did not replace unknown state: active=%v code=%d error=%q", active, code, message)
	}
}

func TestDispatchAptUpgradeStream_emitsLinesAndExit(t *testing.T) {
	resetAptUpgradeState()
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		_ = emit("Setting up pkg-a")
		_ = emit("Processing triggers")
		return 0, nil
	})
	defer resetAptUpgradeState()

	pr, pw := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw)
		_ = pw.Close()
	}()

	events := readStreamEvents(t, pr)
	if len(events) < 4 {
		t.Fatalf("events: %+v", events)
	}
	if events[0].Type != "line" || !strings.Contains(events[0].Data, "starting apt-get upgrade") {
		t.Fatalf("start: %+v", events[0])
	}
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 0 {
		t.Fatalf("exit: %+v", last)
	}
}

func TestDispatchAptStream_autoremove(t *testing.T) {
	resetAptUpgradeState()
	SetAptActionStreamHookForTest(func(_ context.Context, action string, emit func(string) error) (int, error) {
		if action != "autoremove" {
			t.Fatalf("action: %q", action)
		}
		_ = emit("Removing orphan-pkg")
		return 0, nil
	})
	defer resetAptUpgradeState()

	pr, pw := io.Pipe()
	go func() {
		dispatchAptStream(pw, "autoremove")
		_ = pw.Close()
	}()
	events := readStreamEvents(t, pr)
	if !strings.Contains(events[0].Data, "starting apt-get autoremove") {
		t.Fatalf("start: %+v", events[0])
	}
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 0 {
		t.Fatalf("exit: %+v", last)
	}
}

func TestDispatchAptStream_unknownAction(t *testing.T) {
	resetAptUpgradeState()
	defer resetAptUpgradeState()

	pr, pw := io.Pipe()
	go func() {
		dispatchAptStream(pw, "purge")
		_ = pw.Close()
	}()
	events := readStreamEvents(t, pr)
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != -1 || !strings.Contains(last.Error, "unknown apt action") {
		t.Fatalf("exit: %+v", last)
	}
}

func TestDispatchAptStreamExecutionErrorCannotReportZeroExit(t *testing.T) {
	resetAptUpgradeState()
	overrideAptActionLogForTest(t)
	defer resetAptUpgradeState()
	SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) {
		return 0, fmt.Errorf("execution failed")
	})
	var output bytes.Buffer
	dispatchAptUpgradeStream(&output)
	events := readStreamEvents(t, &output)
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 1 || last.Error == "" {
		t.Fatalf("execution error reported as success: %+v", last)
	}
}

func TestDispatchAptStream_singleFlightAttach(t *testing.T) {
	resetAptUpgradeState()
	overrideAptActionLogForTest(t)
	defer func() {
		resetAptUpgradeState()
	}()

	started := make(chan struct{})
	SetAptActionStreamHookForTest(func(_ context.Context, action string, emit func(string) error) (int, error) {
		if action != "upgrade" {
			t.Fatalf("primary action: %q", action)
		}
		close(started)
		_ = emit("primary-line")
		time.Sleep(300 * time.Millisecond)
		return 7, nil
	})

	pr1, pw1 := io.Pipe()
	go func() {
		dispatchAptStream(pw1, "upgrade")
		_ = pw1.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, pr1) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("primary did not start")
	}

	pr2, pw2 := io.Pipe()
	go func() {
		dispatchAptStream(pw2, "autoremove")
		_ = pw2.Close()
	}()
	events := readStreamEvents(t, pr2)
	if !strings.Contains(events[0].Data, "attaching to apt action already in progress") {
		t.Fatalf("attach banner: %+v", events[0])
	}
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 7 {
		t.Fatalf("attach exit: %+v", last)
	}
	_ = pr1.Close()
}

func TestDispatchAptUpgradeStream_attachToRunning(t *testing.T) {
	resetAptUpgradeState()
	overrideAptActionLogForTest(t)
	defer func() {
		resetAptUpgradeState()
	}()

	started := make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		close(started)
		_ = emit("primary-line")
		time.Sleep(200 * time.Millisecond)
		return 0, nil
	})

	pr1, pw1 := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw1)
		_ = pw1.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, pr1) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("primary did not start")
	}

	pr2, pw2 := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw2)
		_ = pw2.Close()
	}()
	events := readStreamEvents(t, pr2)
	if !strings.Contains(events[0].Data, "attaching to apt action already in progress") {
		t.Fatalf("attach banner: %+v", events[0])
	}
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 0 {
		t.Fatalf("attach exit: %+v", last)
	}
	_ = pr1.Close()
}

func TestDispatchAptUpgradeStream_heartbeat(t *testing.T) {
	resetAptUpgradeState()
	setAptActionHeartbeatIntervalForTest(50 * time.Millisecond)
	defer func() {
		setAptActionHeartbeatIntervalForTest(15 * time.Second)
		resetAptUpgradeState()
	}()

	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		time.Sleep(200 * time.Millisecond)
		_ = emit("done")
		return 0, nil
	})

	pr, pw := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw)
		_ = pw.Close()
	}()
	events := readStreamEvents(t, pr)
	var heartbeat bool
	for _, ev := range events {
		if ev.Type == "line" && strings.Contains(ev.Data, "still working") {
			heartbeat = true
		}
	}
	if !heartbeat {
		t.Fatalf("expected heartbeat line: %+v", events)
	}
}

func TestDispatchAptUpgradeStream_clientDisconnectDoesNotCancelApt(t *testing.T) {
	resetAptUpgradeState()
	hookDone := make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		_ = emit("line-one")
		time.Sleep(50 * time.Millisecond)
		_ = emit("line-two")
		close(hookDone)
		return 0, nil
	})
	defer resetAptUpgradeState()

	client, server := net.Pipe()
	go func() {
		dispatchAptUpgradeStream(server)
		_ = server.Close()
	}()
	br := bufio.NewReader(client)
	_, _ = br.ReadBytes('\n')
	_ = client.Close()
	select {
	case <-hookDone:
	case <-time.After(3 * time.Second):
		t.Fatal("apt hook did not finish after client disconnect")
	}
}

func TestSocketRoundTrip_aptUpgradeStream(t *testing.T) {
	resetAptUpgradeState()
	overrideAptActionLogForTest(t)
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		_ = emit("mock upgrade line")
		return 0, nil
	})
	defer resetAptUpgradeState()

	sock := shortTempSock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, sock) }()
	joinTestBroker(t, cancel, serveErr)

	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if conn == nil {
		select {
		case err = <-serveErr:
		default:
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-upgrade-stream"}}); err != nil {
		t.Fatal(err)
	}
	events := readSocketStreamEvents(t, conn)
	if len(events) < 2 {
		t.Fatalf("events: %+v", events)
	}
	if events[len(events)-1].Type != "exit" || events[len(events)-1].Code != 0 {
		t.Fatalf("exit: %+v", events[len(events)-1])
	}
}

func TestSocketRoundTrip_aptAutoremoveStream(t *testing.T) {
	resetAptUpgradeState()
	overrideAptActionLogForTest(t)
	SetAptActionStreamHookForTest(func(_ context.Context, action string, emit func(string) error) (int, error) {
		_ = action
		_ = emit("mock autoremove line")
		return 0, nil
	})
	defer resetAptUpgradeState()

	sock := shortTempSock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(ctx, sock) }()
	joinTestBroker(t, cancel, serveErr)

	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if conn == nil {
		select {
		case err = <-serveErr:
		default:
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-autoremove-stream"}}); err != nil {
		t.Fatal(err)
	}
	events := readSocketStreamEvents(t, conn)
	if events[len(events)-1].Type != "exit" || events[len(events)-1].Code != 0 {
		t.Fatalf("exit: %+v", events[len(events)-1])
	}
}
