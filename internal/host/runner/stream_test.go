// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/hostd"
)

func shortTempSock(t *testing.T) string {
	t.Helper()
	// Keep socket paths short on Windows too: t.TempDir includes the full
	// subtest name, which can exceed the AF_UNIX path limit.
	dir, err := os.MkdirTemp(".", ".sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "s.sock")
}

func TestPrivilegedStream_readsNDJSONLines(t *testing.T) {
	hostd.SetBypassPeerCheckForTest(true)
	hostd.SetAptActionLogPathOverrideForTest(filepath.Join(t.TempDir(), "apt-action.log"))
	t.Cleanup(func() { hostd.ResetAptActionStateForTest(); hostd.SetAptActionLogPathOverrideForTest("") })
	sock := shortTempSock(t)

	hostd.ResetAptUpgradeStateForTest()
	hostd.SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
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
	hostd.SetBypassPeerCheckForTest(true)
	hostd.SetAptActionLogPathOverrideForTest(filepath.Join(t.TempDir(), "apt-action.log"))
	t.Cleanup(func() { hostd.ResetAptActionStateForTest(); hostd.SetAptActionLogPathOverrideForTest("") })
	sock := shortTempSock(t)

	hostd.ResetAptUpgradeStateForTest()
	hostd.SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
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

	err := PrivilegedStream(context.Background(), func(_ []byte) error {
		return io.ErrClosedPipe
	}, "apt-upgrade-stream")
	if err != nil {
		t.Fatal(err)
	}
	// The relay returns before the broker finishes. Wait for its result before
	// resetting globals/removing the log fixture; cancellation must not cancel APT.
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelWait()
	for {
		payload, err := Privileged(waitCtx, "apt-action-status")
		if err != nil {
			t.Fatal(err)
		}
		var status struct {
			Active bool `json:"active"`
		}
		if err := json.Unmarshal(payload, &status); err != nil {
			t.Fatal(err)
		}
		if !status.Active {
			break
		}
		time.Sleep(10 * time.Millisecond)
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

func TestPrivilegedStreamRejectsEOFWithoutExit(t *testing.T) {
	socket := shortTempSock(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
	brokerDone := make(chan struct{})
	go func() {
		defer close(brokerDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req brokerRequest
		if json.NewDecoder(conn).Decode(&req) != nil {
			return
		}
		_, _ = io.WriteString(conn, "{\"type\":\"line\",\"data\":\"working\"}\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = PrivilegedStream(ctx, func([]byte) error { return nil }, "apt-upgrade-stream")
	<-brokerDone
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("incomplete stream accepted: %v", err)
	}
}
