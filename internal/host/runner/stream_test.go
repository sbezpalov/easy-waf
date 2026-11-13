// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	result := streamWireFixture(t, func(conn net.Conn) error {
		_, err := io.WriteString(conn, "{\"type\":\"line\",\"data\":\"alpha\"}\n{\"type\":\"line\",\"data\":\"beta\"}\n{\"type\":\"exit\",\"code\":2}\n")
		return err
	})

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
	if err := result(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedStream_stopsRelayOnWriteError(t *testing.T) {
	result := streamWireFixture(t, func(conn net.Conn) error {
		if _, err := io.WriteString(conn, "{\"type\":\"line\",\"data\":\"one\"}\n{\"type\":\"line\",\"data\":\"two\"}\n{\"type\":\"exit\",\"code\":0}\n"); err != nil {
			return err
		}
		var data [1]byte
		if _, err := conn.Read(data[:]); !errors.Is(err, io.EOF) {
			return fmt.Errorf("relay retained its socket after callback failure: %v", err)
		}
		return nil
	})

	calls := 0
	err := PrivilegedStream(context.Background(), func(_ []byte) error {
		calls++
		return io.ErrClosedPipe
	}, "apt-upgrade-stream")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("relay called failed subscriber again: %d callbacks", calls)
	}
	if err := result(); err != nil {
		t.Fatal(err)
	}
}

// Relay tests own their wire peer; actual broker/worker package ownership is
// exercised by hostd's real systemd integration fixture.
func streamWireFixture(t *testing.T, body func(net.Conn) error) func() error {
	return streamWireFixtureFor(t, "apt-upgrade-stream", body)
}

func streamWireFixtureFor(t *testing.T, opcode string, body func(net.Conn) error) func() error {
	t.Helper()
	socket := shortTempSock(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			result = err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			result = err
			return
		}
		var request brokerRequest
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			result = err
			return
		}
		if len(request.Argv) != 1 || request.Argv[0] != opcode {
			result = fmt.Errorf("unexpected relay request: %v", request.Argv)
			return
		}
		result = body(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("relay wire fixture did not stop")
		}
	})
	return func() error {
		select {
		case <-done:
			return result
		case <-time.After(4 * time.Second):
			return errors.New("relay wire fixture did not complete")
		}
	}
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
