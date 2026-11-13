// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestBrokerCallsStopWaitingWhenContextEnds(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, deadline := range []bool{false, true} {
			name := "regular"
			if stream {
				name = "stream"
			}
			if deadline {
				name += "/deadline"
			} else {
				name += "/cancel"
			}
			t.Run(name, func(t *testing.T) {
				socket := shortTempSock(t)
				listener, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
				requestRead := make(chan error, 1)
				release := make(chan struct{})
				var once sync.Once
				releaseBroker := func() { once.Do(func() { close(release) }) }
				defer releaseBroker()
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						requestRead <- err
						return
					}
					defer conn.Close()
					var req brokerRequest
					requestRead <- json.NewDecoder(conn).Decode(&req)
					<-release // deliberately do not answer the decoded request
				}()
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
				}
				defer cancel()
				result := make(chan error, 1)
				go func() {
					if stream {
						result <- PrivilegedStream(ctx, func([]byte) error { return nil }, "apt-upgrade-stream")
					} else {
						_, err := Privileged(ctx, "nft-list")
						result <- err
					}
				}()
				select {
				case err := <-requestRead:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("broker did not receive request")
				}
				if !deadline {
					cancel()
				}
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("error = %v, want %v", err, want)
					}
				case <-time.After(4 * time.Second):
					// Let a broken implementation exit instead of leaking a blocked test.
					releaseBroker()
					<-result
					t.Fatal("context ended but broker call remained blocked")
				}
			})
		}
	}
}

func TestContextCancellationUnblocksBrokerWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, broker := net.Pipe()
	defer client.Close()
	defer broker.Close()
	stop := closeOnCancel(ctx, client)
	defer stop()
	result := make(chan error, 1)
	go func() {
		// net.Pipe has no buffer and the peer never reads this request.
		_, err := client.Write([]byte("request"))
		result <- brokerIOError(ctx, err)
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("write cancellation reason lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request remained blocked writing to broker")
	}
}
