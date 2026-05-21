package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
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
	if len(events) < 3 {
		t.Fatalf("events: %+v", events)
	}
	if events[0].Type != "line" || events[0].Data != "Setting up pkg-a" {
		t.Fatalf("first: %+v", events[0])
	}
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code != 0 {
		t.Fatalf("exit: %+v", last)
	}
}

func TestDispatchAptUpgradeStream_singleFlight(t *testing.T) {
	resetAptUpgradeState()
	started := make(chan struct{})
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, nil
	}
	defer resetAptUpgradeState()

	pr1, pw1 := io.Pipe()
	aptCtx, aptCancel := context.WithCancel(context.Background())
	aptUpgradeStreamHook = func(ctx context.Context, emit func(string) error) (int, error) {
		close(started)
		<-aptCtx.Done()
		return 0, nil
	}
	go func() {
		dispatchAptUpgradeStream(pw1)
		_ = pw1.Close()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first upgrade did not start")
	}

	pr2, pw2 := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw2)
		_ = pw2.Close()
	}()
	events := readStreamEvents(t, pr2)
	if len(events) != 1 || events[0].Type != "exit" || events[0].Code != -1 {
		t.Fatalf("second: %+v", events)
	}
	if events[0].Error == "" {
		t.Fatal("expected already in progress error")
	}

	aptCancel()
	aptUpgradeEnd()
	_ = pr1.Close()
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
