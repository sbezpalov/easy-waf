// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAPTProxyWriteCannotOutliveItsSocketBudget(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	done := make(chan error, 1)
	go func() {
		_, err := (aptProxyWriter{conn: proxy, expires: time.Now().Add(25 * time.Millisecond)}).Write([]byte("output"))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("stalled proxy write lost its deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unread client retained a proxy write beyond its budget")
	}
}

func aptSocketPair(t *testing.T, handler func(net.Conn)) (net.Conn, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("unix", shortTempSock(t))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			handler(conn)
		}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("APT fixture handler did not stop")
		}
	})
	return client, done
}

func TestAPTWorkerCannotDispatchOtherHostOperations(t *testing.T) {
	previous := peerCheckBypassed()
	SetBypassPeerCheckForTest(true)
	t.Cleanup(func() { SetBypassPeerCheckForTest(previous) })
	for _, op := range []string{"systemctl", "nft-list", "apt-worker", "restart-after-packages", "apt-unknown"} {
		t.Run(op, func(t *testing.T) {
			runner := &mockRunner{}
			client, done := aptSocketPair(t, func(conn net.Conn) {
				handleConnRole(t.Context(), conn, &Dispatcher{Runner: runner}, aptWorkerSocket)
			})
			if err := json.NewEncoder(client).Encode(Request{Argv: []string{op, "reboot"}}); err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.NewDecoder(client).Decode(&response); err != nil {
				t.Fatal(err)
			}
			<-done
			if response.OK || runner.lastName != "" || !strings.Contains(response.Error, "not allowed") {
				t.Fatalf("worker escaped APT allowlist: %+v command=%q", response, runner.lastName)
			}
		})
	}
}

func TestAPTProxyUnavailableDoesNotExecuteLocally(t *testing.T) {
	runner := &aptMutationRunner{}
	previous := DefaultRunner
	DefaultRunner = runner
	t.Cleanup(func() { DefaultRunner = previous })
	for _, op := range []string{"apt-update", "apt-upgrade-stream", "apt-action-attach-stream"} {
		t.Run(op, func(t *testing.T) {
			client, proxy := net.Pipe()
			socket := shortTempSock(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer proxy.Close()
				proxyAPTRequest(t.Context(), proxy, Request{Argv: []string{op}}, socket)
			}()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if isAPTStreamOpcode(op) {
				events := readSocketStreamEvents(t, client)
				if len(events) != 1 || events[0].Code != -1 || !strings.Contains(events[0].Error, "service unavailable") {
					t.Fatalf("missing explicit stream failure: %+v", events)
				}
			} else {
				var response Response
				if err := json.NewDecoder(client).Decode(&response); err != nil || response.OK || !strings.Contains(response.Error, "service unavailable") {
					t.Fatalf("missing explicit RPC failure: %+v %v", response, err)
				}
			}
			<-done
		})
	}
	if runner.calls.Load() != 0 {
		t.Fatal("unavailable worker fell back to broker-local package execution")
	}
}

func TestAPTProxyPreservesRequestAndWireResponse(t *testing.T) {
	previous := peerCheckBypassed()
	SetBypassPeerCheckForTest(true)
	t.Cleanup(func() { SetBypassPeerCheckForTest(previous) })
	for _, op := range []string{"apt-action-status", "apt-action-attach-stream"} {
		t.Run(op, func(t *testing.T) {
			request := Request{Argv: []string{op, strings.Repeat("a", 32)}}
			listener, err := net.Listen("unix", shortTempSock(t))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan Request, 1)
			workerDone := make(chan struct{})
			go func() {
				defer close(workerDone)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				var got Request
				if json.NewDecoder(conn).Decode(&got) != nil {
					return
				}
				observed <- got
				if isAPTStreamOpcode(op) {
					_, _ = io.WriteString(conn, "{\"type\":\"line\",\"data\":\"fixture\"}\n{\"type\":\"exit\",\"code\":7}\n")
				} else {
					_ = json.NewEncoder(conn).Encode(failResp("fixture result", 7))
				}
			}()
			client, proxy := net.Pipe()
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				defer proxy.Close()
				proxyAPTRequest(context.Background(), proxy, request, listener.Addr().String())
			}()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if isAPTStreamOpcode(op) {
				events := readSocketStreamEvents(t, client)
				if len(events) != 2 || events[0].Data != "fixture" || events[1].Code != 7 {
					t.Fatalf("changed NDJSON response: %+v", events)
				}
			} else {
				var response Response
				if err := json.NewDecoder(client).Decode(&response); err != nil || response.Code != 7 || response.Error != "fixture result" {
					t.Fatalf("changed RPC response: %+v %v", response, err)
				}
			}
			<-proxyDone
			<-workerDone
			if got := <-observed; !slices.Equal(got.Argv, request.Argv) {
				t.Fatalf("changed selected operation: %v", got.Argv)
			}
		})
	}
}
