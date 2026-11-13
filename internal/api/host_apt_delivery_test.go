// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type aptHTTPDeliveryProbe struct {
	*streamSpy
	deadlines []time.Time
	phase     string
	failure   error
	attempts  int
}

func (w *aptHTTPDeliveryProbe) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	if !deadline.IsZero() && w.phase == "deadline" {
		return w.failure
	}
	return nil
}

func (w *aptHTTPDeliveryProbe) Write(p []byte) (int, error) {
	w.attempts++
	if w.phase == "write" {
		return 0, w.failure
	}
	return w.streamSpy.Write(p)
}

func (w *aptHTTPDeliveryProbe) FlushError() error {
	w.Flush()
	if w.phase == "flush" {
		return w.failure
	}
	return nil
}

func TestHostAptHTTPDeliveryBoundsWritesAndPropagatesFailures(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	for _, phase := range []string{"", "deadline", "write", "flush"} {
		t.Run("phase_"+phase, func(t *testing.T) {
			failure := errors.New("fixture client delivery failure")
			var relayErr error
			privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, _ ...string) error {
				relayErr = onLine([]byte(`{"type":"exit","code":0}`))
				return relayErr
			}
			w := &aptHTTPDeliveryProbe{streamSpy: &streamSpy{}, phase: phase, failure: failure}
			start := time.Now()
			(&Server{}).hostAptUpgradeStream(w, httptest.NewRequest(http.MethodPost, "/", nil))
			if phase == "" {
				if relayErr != nil || len(w.deadlines) != 3 || !w.deadlines[0].IsZero() || !w.deadlines[2].IsZero() || w.attempts != 1 || w.flushes != 1 {
					t.Fatalf("healthy delivery left an idle deadline armed: %+v err=%v", w, relayErr)
				}
			} else if !errors.Is(relayErr, failure) || w.attempts > 1 {
				t.Fatalf("failed delivery retried or lost its error: writes=%d err=%v", w.attempts, relayErr)
			}
			if budget := w.deadlines[1].Sub(start); budget < aptHTTPWriteTimeout || budget > aptHTTPWriteTimeout+time.Second {
				t.Fatalf("unexpected HTTP write budget: %s", budget)
			}
		})
	}
}

// Keep real HTTP I/O bounded and expose whether the logger's response wrapper
// passes ResponseController deadlines through to the actual socket.
type aptQuickHTTPWriter struct {
	http.ResponseWriter
	budget time.Duration
}

func (w aptQuickHTTPWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w aptQuickHTTPWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w aptQuickHTTPWriter) Flush() { _ = w.FlushError() }

func (w aptQuickHTTPWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(w.budget)
	}
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(deadline)
}

func TestHostAptHTTPUnreadClientTimesOutThroughLogger(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	result := make(chan error, 1)
	privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, _ ...string) error {
		err := onLine([]byte(`{"type":"line","data":"` + strings.Repeat("x", 6<<20) + `"}`))
		result <- err
		return err
	}
	done := make(chan struct{})
	handler := middleware.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		(&Server{}).hostAptUpgradeStream(w, r)
	}))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(aptQuickHTTPWriter{w, 50 * time.Millisecond}, r)
	}))
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			if err := c.(*net.TCPConn).SetWriteBuffer(4096); err != nil {
				t.Errorf("bound fixture send buffer: %v", err)
			}
		}
	}
	server.Start()
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.(*net.TCPConn).SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		<-done
		t.Fatal("unread HTTP client retained the API relay")
	}
	var timeout net.Error
	if err := <-result; !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("write/flush error did not reach broker relay: %v", err)
	}
}

func TestHostAptHTTP2IdleWaitDoesNotKeepWriteDeadlineArmed(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	privilegedStreamFn = func(ctx context.Context, onLine func([]byte) error, _ ...string) error {
		if err := onLine([]byte(`{"type":"line","data":"waiting"}`)); err != nil {
			return err
		}
		timer := time.NewTimer(400 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		return onLine([]byte(`{"type":"exit","code":0}`))
	}
	handler := middleware.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(&Server{}).hostAptUpgradeStream(w, r)
	}))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(aptQuickHTTPWriter{w, 200 * time.Millisecond}, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.ProtoMajor != 2 || !strings.Contains(string(data), `"code":0`) {
		t.Fatalf("idle HTTP/2 stream was terminated by a stale write deadline: proto=%s body=%q err=%v", resp.Proto, data, err)
	}
}
