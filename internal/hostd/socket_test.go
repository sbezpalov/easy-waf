// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

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

// Real broker streams finish at an explicit terminal event, independent of
// socket EOF. Keep readStreamEvents for in-memory tests that check all output.
func readSocketStreamEvents(t *testing.T, conn net.Conn) []streamEvent {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	var events []streamEvent
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			t.Fatalf("socket stream ended before terminal event: %v", err)
		}
		var event streamEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
		switch event.Type {
		case "exit":
			var terminal struct {
				Code *int `json:"code"`
			}
			if err := json.Unmarshal(line, &terminal); err != nil || terminal.Code == nil {
				t.Fatalf("socket terminal event has no integer code: %s", line)
			}
			return events
		case "line":
		default:
			t.Fatalf("unknown socket stream event: %+v", event)
		}
	}
}

func joinTestBroker(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("test broker shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("test broker accept loop did not stop")
		}
	})
}

func TestSocketStreamReaderCompletesBeforePeerEOF(t *testing.T) {
	client, server := net.Pipe()
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(server, "{\"type\":\"line\",\"data\":\"output\"}\n{\"type\":\"exit\",\"code\":7}\n")
		<-release // A terminal event must complete reading before this close.
		_ = server.Close()
		done <- err
	}()
	t.Cleanup(func() {
		close(release)
		_ = client.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	events := readSocketStreamEvents(t, client)
	if len(events) != 2 || events[1].Code != 7 {
		t.Fatalf("terminal output/result lost: %+v", events)
	}
}
