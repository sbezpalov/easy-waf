// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBrokerStreamRequiresValidTerminalEvent(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantErr     bool
		wantLines   int
	}{
		{"success", "{\"type\":\"line\",\"data\":\"hello\"}\n{\"type\":\"exit\",\"code\":0}\n", false, 2},
		{"apt failure", "{\"type\":\"exit\",\"code\":2,\"error\":\"apt failed\"}\n", false, 1},
		{"empty", "", true, 0},
		{"only output", "{\"type\":\"line\",\"data\":\"still running\"}\n", true, 1},
		{"partial JSON", "{\"type\":\"exit\",", true, 0},
		{"unterminated exit", "{\"type\":\"exit\",\"code\":0}", true, 0},
		{"invalid JSON", "not json\n", true, 0},
		{"missing code", "{\"type\":\"exit\"}\n", true, 0},
		{"wrong code type", "{\"type\":\"exit\",\"code\":\"0\"}\n", true, 0},
		{"contradictory exit", "{\"type\":\"exit\",\"code\":0,\"error\":\"failed\"}\n", true, 0},
		{"unknown event", "{\"type\":\"unknown\"}\n", true, 0},
		{"blank lines", "\n \r\n{\"type\":\"exit\",\"code\":0}\r\n", false, 1},
		{"oversized", strings.Repeat("x", maxBrokerStreamRecordBytes+1) + "\n", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := 0
			err := relayBrokerStream(context.Background(), strings.NewReader(tc.input), func([]byte) error { lines++; return nil })
			if (err != nil) != tc.wantErr || lines != tc.wantLines {
				t.Fatalf("err=%v lines=%d, want error=%v lines=%d", err, lines, tc.wantErr, tc.wantLines)
			}
		})
	}
}

type failedStreamReader struct{}

func (failedStreamReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestBrokerStreamFinishesAtExitWithoutWaitingForEOF(t *testing.T) {
	input := io.MultiReader(strings.NewReader("{\"type\":\"exit\",\"code\":0}\n"), failedStreamReader{})
	if err := relayBrokerStream(context.Background(), input, func([]byte) error { return nil }); err != nil {
		t.Fatalf("valid terminal event lost to a later transport error: %v", err)
	}
}

func TestBrokerStreamKeepsDrainingAfterReceiverFailure(t *testing.T) {
	input := "{\"type\":\"line\",\"data\":\"one\"}\n{\"type\":\"line\",\"data\":\"two\"}\n{\"type\":\"exit\",\"code\":0}\n"
	calls := 0
	err := relayBrokerStream(context.Background(), strings.NewReader(input), func([]byte) error { calls++; return io.ErrClosedPipe })
	if err != nil || calls != 1 {
		t.Fatalf("draining failed: err=%v calls=%d", err, calls)
	}
	err = relayBrokerStream(context.Background(), strings.NewReader("{\"type\":\"line\"}\n"), func([]byte) error { return io.ErrClosedPipe })
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("receiver failure hid a truncated broker stream: %v", err)
	}
}
