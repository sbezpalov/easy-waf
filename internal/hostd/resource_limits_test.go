// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostRequestByteLimit(t *testing.T) {
	for _, size := range []int{maxHostRequestBytes, 8 * maxHostRequestBytes} {
		request := `{"argv":["nft-list","` + strings.Repeat("x", size) + `"]}`
		reader := &io.LimitedReader{R: strings.NewReader(request), N: int64(len(request))}
		if _, err := ReadRequest(reader); err == nil {
			t.Errorf("accepted request larger than %d bytes", maxHostRequestBytes)
		}
		if consumed := int64(len(request)) - reader.N; consumed > maxHostRequestBytes+1 {
			t.Errorf("read %d bytes before rejecting oversized request", consumed)
		}
	}
	for _, request := range []string{`{"argv":["nft-list"]}`, `{"argv":["apt-action-attach-stream","` + strings.Repeat("a", 32) + `"]}`} {
		if _, err := ReadRequest(strings.NewReader(request)); err != nil {
			t.Fatalf("rejected existing protocol: %v", err)
		}
	}
	if _, err := ReadRequest(strings.NewReader(`{"argv":["nft-list"],"unknown":true}`)); err == nil {
		t.Fatal("request size check disabled strict field validation")
	}
	// The exact byte limit is inclusive; leading whitespace counts too.
	request := `{"argv":["nft-list"]}`
	if _, err := ReadRequest(strings.NewReader(strings.Repeat(" ", maxHostRequestBytes-len(request)) + request)); err != nil {
		t.Fatalf("exact-size request was rejected: %v", err)
	}
}

func TestOversizedHostRequestCannotExecute(t *testing.T) {
	runner := &mockRunner{}
	client, done := aptSocketPair(t, func(conn net.Conn) {
		handleConnRole(t.Context(), conn, &Dispatcher{Runner: runner}, localSocket)
	})
	written := make(chan error, 1)
	go func() {
		written <- json.NewEncoder(client).Encode(Request{Argv: []string{"nft-list", strings.Repeat("x", 2*maxHostRequestBytes)}})
	}()
	var response Response
	err := json.NewDecoder(client).Decode(&response)
	var transport net.Error
	// Closing with unread excess bytes can discard the reply and reset the
	// socket on Windows/Linux. Either rejection must refuse command execution.
	if err == nil {
		if response.OK || !strings.Contains(response.Error, "invalid request") {
			t.Errorf("oversized request had no protocol rejection: %+v", response)
		}
	} else if !errors.Is(err, io.EOF) && (!errors.As(err, &transport) || transport.Timeout()) {
		t.Errorf("oversized request did not fail closed promptly: %v", err)
	}
	_ = client.Close()
	if writeErr := <-written; writeErr != nil {
		t.Logf("oversized writer stopped after rejection: %v", writeErr)
	}
	<-done
	if runner.lastName != "" {
		t.Fatal("oversized request reached the command runner")
	}
}

func TestHostSocketAdmissionIsBoundedAndReusable(t *testing.T) {
	previous := DefaultRunner
	defer func() { DefaultRunner = previous }()
	started := make(chan struct{}, 2*maxHostConnections)
	release := make(chan struct{})
	var calls atomic.Int32
	DefaultRunner = packageRestartRunner(func(context.Context, string, ...string) ([]byte, []byte, int, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return []byte("fixture"), nil, 0, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	socket := shortTempSock(t)
	done := make(chan error, 1)
	go func() { done <- serveSocket(ctx, socket, localSocket) }()
	var clients []net.Conn
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		for _, client := range clients {
			_ = client.Close()
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("saturated listener did not stop")
		}
	})
	dial := func() net.Conn {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			client, err := net.DialTimeout("unix", socket, 50*time.Millisecond)
			if err == nil {
				clients = append(clients, client)
				if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				return client
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for i := 0; i < maxHostConnections; i++ {
		client := dial()
		if err := json.NewEncoder(client).Encode(Request{Argv: []string{"nft-list"}}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatalf("admitted handler %d did not reach its command", i)
		}
	}
	extra := dial()
	if err := extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(extra, `{"argv":["nft-list"]}`)
	var probe [1]byte
	_, err := extra.Read(probe[:])
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Errorf("excess connection was retained instead of closed: %v", err)
	}
	if got := calls.Load(); got != maxHostConnections {
		t.Errorf("excess connection executed a command: calls=%d", got)
	}
	close(release)
	released = true
	for _, client := range clients[:maxHostConnections] {
		var response Response
		if err := json.NewDecoder(client).Decode(&response); err != nil || !response.OK || response.Stdout != "fixture" {
			t.Fatalf("saturation interrupted admitted work: %+v %v", response, err)
		}
	}
	client := dial()
	if err := json.NewEncoder(client).Encode(Request{Argv: []string{"nft-list"}}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil || !response.OK {
		t.Fatalf("completed handlers did not release admission: %+v %v", response, err)
	}
}
