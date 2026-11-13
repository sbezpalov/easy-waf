// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

func TestAPTLogDownloadRequiresCompleteValidReadOnlyProtocol(t *testing.T) {
	for _, fixture := range []struct {
		name, wire, text string
		ok               bool
	}{
		{"complete", "{\"type\":\"line\",\"data\":\"a\\n世🙂\"}\n{\"type\":\"exit\",\"code\":0}\n", "a\n世🙂", true},
		{"empty", "{\"type\":\"exit\",\"code\":0}\n", "", true},
		{"missing_exit", "{\"type\":\"line\",\"data\":\"partial\"}\n", "partial", false},
		{"unterminated", "{\"type\":\"exit\",\"code\":0}", "", false},
		{"missing_code", "{\"type\":\"exit\"}\n", "", false},
		{"failed_exit", "{\"type\":\"line\",\"data\":\"partial\"}\n{\"type\":\"exit\",\"code\":-1,\"error\":\"read failed\"}\n", "partial", false},
		{"contradiction", "{\"type\":\"exit\",\"code\":0,\"error\":\"failed\"}\n", "", false},
		{"unknown", "{\"type\":\"other\"}\n", "", false},
		{"old_broker", "{\"ok\":false,\"error\":\"unknown op\",\"code\":1}\n", "", false},
		{"invalid", "no json\n", "", false},
		{"chunk_limit", "{\"type\":\"line\",\"data\":\"" + strings.Repeat("x", 3*(hostspec.APTLogChunkBytes+3)+1) + "\"}\n", "", false},
		{"frame_limit", strings.Repeat(" ", hostspec.MaxAPTLogFrameBytes+1) + "\n", "", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var out bytes.Buffer
			err := copyAPTLogEvents(t.Context(), strings.NewReader(fixture.wire), &out)
			if (err == nil) != fixture.ok || out.String() != fixture.text {
				t.Fatalf("incomplete/oversized protocol accepted or data changed: success=%v bytes=%d err=%v", err == nil, out.Len(), err)
			}
		})
	}
}

type failedAPTLogSink struct{}

func (failedAPTLogSink) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type aptLogCountingSink struct{ bytes int64 }

func (s *aptLogCountingSink) Write(p []byte) (int, error) {
	s.bytes += int64(len(p))
	return len(p), nil
}

func (s *aptLogCountingSink) WriteString(p string) (int, error) {
	s.bytes += int64(len(p))
	return len(p), nil
}

func TestAPTLogDownloadRejectsDecodedTotalBeforeWritingExcess(t *testing.T) {
	const limit = 192 << 20
	wire := "{\"type\":\"line\",\"data\":\"" + strings.Repeat("x", 32<<10) + "\"}\n"
	readers := make([]io.Reader, limit/(32<<10)+2)
	for i := range len(readers) - 1 {
		readers[i] = strings.NewReader(wire)
	}
	readers[len(readers)-1] = strings.NewReader("{\"type\":\"exit\",\"code\":0}\n")
	sink := &aptLogCountingSink{}
	// Readers share one small frame: exercise the real total-size boundary
	// without allocating or storing a192 MiB test string/file.
	if err := copyAPTLogEvents(t.Context(), io.MultiReader(readers...), sink); err == nil || sink.bytes != limit {
		t.Fatalf("decoded download exceeded its total budget: bytes=%d err=%v", sink.bytes, err)
	}
}

func TestAPTLogDownloadClosesImmediatelyOnReadOnlySinkFailure(t *testing.T) {
	result := streamWireFixtureFor(t, "apt-action-log-stream", func(conn net.Conn) error {
		if _, err := io.WriteString(conn, "{\"type\":\"line\",\"data\":\"saved\"}\n"); err != nil {
			return err
		}
		var b [1]byte
		_, err := conn.Read(b[:]) // No terminal: a failed sink must not keep draining.
		if !errors.Is(err, io.EOF) {
			return errors.New("saved-log reader retained its failed sink/socket")
		}
		return nil
	})
	if err := DownloadAPTLog(t.Context(), failedAPTLogSink{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("sink error was lost: %v", err)
	}
	if err := result(); err != nil {
		t.Fatal(err)
	}
}

func TestAPTLogDownloadContextEndsSocketWait(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			ready := make(chan struct{})
			result := streamWireFixtureFor(t, "apt-action-log-stream", func(conn net.Conn) error {
				close(ready)
				var b [1]byte
				_, err := conn.Read(b[:])
				if !errors.Is(err, io.EOF) {
					return errors.New("canceled download retained broker connection")
				}
				return nil
			})
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), time.Second)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- DownloadAPTLog(ctx, io.Discard) }()
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("download peer did not receive the fixed read-only request")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				cause := context.Canceled
				if deadline {
					cause = context.DeadlineExceeded
				}
				if !errors.Is(err, cause) {
					t.Fatalf("download lost context cause: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("download retained a canceled read")
			}
			if err := result(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
