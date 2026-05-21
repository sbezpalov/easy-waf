package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetAptUpgradeState() {
	ResetAptUpgradeStateForTest()
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

func TestDispatchAptUpgradeStream_emitsLinesAndExit(t *testing.T) {
	resetAptUpgradeState()
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("Setting up pkg-a")
		_ = emit("Processing triggers")
		return 0, nil
	}
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

func TestDispatchAptUpgradeStream_attachToRunning(t *testing.T) {
	resetAptUpgradeState()
	aptUpgradeLogPathOverride = filepath.Join(t.TempDir(), "apt-upgrade.log")
	defer func() { aptUpgradeLogPathOverride = "" }()

	started := make(chan struct{})
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		close(started)
		_ = emit("primary-line")
		time.Sleep(200 * time.Millisecond)
		return 0, nil
	}
	defer resetAptUpgradeState()

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
	if len(events) < 2 {
		t.Fatalf("attach events: %+v", events)
	}
	if !strings.Contains(events[0].Data, "attaching to upgrade already in progress") {
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
	aptUpgradeHeartbeatInterval = 50 * time.Millisecond
	defer func() {
		aptUpgradeHeartbeatInterval = 15 * time.Second
		resetAptUpgradeState()
	}()

	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		time.Sleep(200 * time.Millisecond)
		_ = emit("done")
		return 0, nil
	}

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
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("line-one")
		time.Sleep(50 * time.Millisecond)
		_ = emit("line-two")
		close(hookDone)
		return 0, nil
	}
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
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("mock upgrade line")
		return 0, nil
	}
	defer resetAptUpgradeState()

	dir := t.TempDir()
	sock := dir + "/hostd.sock"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, sock) }()

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
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-upgrade-stream"}}); err != nil {
		t.Fatal(err)
	}
	events := readStreamEvents(t, conn)
	if len(events) < 2 {
		t.Fatalf("events: %+v", events)
	}
	if events[len(events)-1].Type != "exit" || events[len(events)-1].Code != 0 {
		t.Fatalf("exit: %+v", events[len(events)-1])
	}
}
