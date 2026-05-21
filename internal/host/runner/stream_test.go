package runner

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/hostd"
)

func TestPrivilegedStream_readsNDJSONLines(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "hostd.sock")

	hostd.ResetAptUpgradeStateForTest()
	hostd.SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("alpha")
		_ = emit("beta")
		return 2, nil
	})
	defer hostd.ResetAptUpgradeStateForTest()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = hostd.Serve(ctx, sock) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
		if BrokerAvailableWithSocket(sock) {
			break
		}
	}
	t.Setenv("EASY_WAF_HOSTD_SOCKET", sock)

	var lines [][]byte
	err := PrivilegedStream(context.Background(), func(line []byte) error {
		lines = append(lines, append([]byte(nil), line...))
		return nil
	}, "apt-upgrade-stream")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) < 3 {
		t.Fatalf("lines: %d", len(lines))
	}
	var ev struct {
		Type string `json:"type"`
		Code int    `json:"code"`
	}
	if json.Unmarshal(lines[len(lines)-1], &ev) != nil || ev.Type != "exit" || ev.Code != 2 {
		t.Fatalf("exit line: %s", lines[len(lines)-1])
	}
}

func TestPrivilegedStream_stopsRelayOnWriteError(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "hostd.sock")

	hostd.ResetAptUpgradeStateForTest()
	hostd.SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		_ = emit("one")
		_ = emit("two")
		return 0, nil
	})
	defer hostd.ResetAptUpgradeStateForTest()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = hostd.Serve(ctx, sock) }()
	time.Sleep(100 * time.Millisecond)
	t.Setenv("EASY_WAF_HOSTD_SOCKET", sock)

	err := PrivilegedStream(context.Background(), func(line []byte) error {
		return io.ErrClosedPipe
	}, "apt-upgrade-stream")
	if err != nil {
		t.Fatal(err)
	}
}

func BrokerAvailableWithSocket(sock string) bool {
	// local helper for test
	c, err := net.Dial("unix", sock)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
