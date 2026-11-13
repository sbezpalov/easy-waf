// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

type aptLogHTTPProbe struct {
	header  http.Header
	code    int
	largest int
	bytes   int
}

func aptLogDownloadFixture(t *testing.T, fn func(context.Context, io.Writer) error) string {
	t.Helper()
	previous, previousSlots := downloadAPTLogFn, aptLogDownloadSlots
	downloadAPTLogFn, aptLogDownloadSlots = fn, make(chan struct{}, 2)
	t.Cleanup(func() { downloadAPTLogFn, aptLogDownloadSlots = previous, previousSlots })
	dir := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, dir)
	}
	return dir
}

func assertAPTLogTempCleanup(t *testing.T, dir string, file *os.File) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("saved-log temporary file leaked: entries=%d err=%v", len(entries), err)
	}
	if file != nil {
		if _, err := file.Stat(); err == nil {
			t.Fatal("saved-log temporary descriptor was not closed")
		}
	}
}

func TestHostAptSavedLogValidatesBeforeSuccessAndCleansPrivateStorage(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			var file *os.File
			dir := aptLogDownloadFixture(t, func(_ context.Context, w io.Writer) error {
				file = w.(*aptLogSpool).w.(*os.File)
				st, err := file.Stat()
				if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0) {
					t.Fatalf("saved log storage is not private: %v", err)
				}
				if _, err := io.WriteString(w, "saved log\n世🙂\n"); err != nil {
					return err
				}
				if fail {
					return errors.New("private worker diagnostic")
				}
				return nil
			})
			w := httptest.NewRecorder()
			(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if fail {
				if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "saved log") || strings.Contains(w.Body.String(), "private") {
					t.Fatalf("partial failed download became success or leaked detail: code=%d", w.Code)
				}
			} else if w.Code != http.StatusOK || w.Body.String() != "saved log\n世🙂\n" || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("validated plain-text download changed its body or headers")
			}
			assertAPTLogTempCleanup(t, dir, file)
			if len(aptLogDownloadSlots) != 0 {
				t.Fatal("completed download retained admission")
			}
		})
	}
}

func TestHostAptSavedLogLimitsConcurrentDownloadsAndReusesAdmission(t *testing.T) {
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	dir := aptLogDownloadFixture(t, func(context.Context, io.Writer) error {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return nil
	})
	var workers sync.WaitGroup
	t.Cleanup(func() { once.Do(func() { close(release) }); workers.Wait() })
	for range 2 {
		workers.Go(func() {
			w := httptest.NewRecorder()
			(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusOK {
				t.Errorf("admitted download was interrupted: %d", w.Code)
			}
		})
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("admitted download did not start")
		}
	}
	rejected := make(chan *httptest.ResponseRecorder, 1)
	workers.Go(func() {
		w := httptest.NewRecorder()
		(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
		rejected <- w
	})
	var w *httptest.ResponseRecorder
	select {
	case w = <-rejected:
	case <-time.After(time.Second):
		t.Fatal("excess download waited for storage admission instead of being rejected")
	}
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" || calls.Load() != 2 {
		t.Fatal("excess download entered storage/worker instead of receiving retry guidance")
	}
	once.Do(func() { close(release) })
	workers.Wait()
	w = httptest.NewRecorder()
	(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || calls.Load() != 3 {
		t.Fatal("completed downloads did not release admission")
	}
	assertAPTLogTempCleanup(t, dir, nil)
}

func TestHostAptSavedLogCancellationCleansStorage(t *testing.T) {
	started := make(chan struct{})
	var file *os.File
	dir := aptLogDownloadFixture(t, func(ctx context.Context, w io.Writer) error {
		file = w.(*aptLogSpool).w.(*os.File)
		if _, err := io.WriteString(w, "partial"); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	joined := false
	go func() {
		defer close(done)
		(&Server{}).hostAptUpgradeLog(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
	}()
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("canceled HTTP fixture did not join")
			}
		}
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel fixture did not start")
	}
	cancel()
	select {
	case <-done:
		joined = true
	case <-time.After(2 * time.Second):
		t.Fatal("canceled download did not close its storage")
	}
	assertAPTLogTempCleanup(t, dir, file)
	if len(aptLogDownloadSlots) != 0 {
		t.Fatal("canceled download retained admission")
	}
}

func TestHostAptSavedLogAuthorizationAndReadOnlyRole(t *testing.T) {
	calls := 0
	aptLogDownloadFixture(t, func(context.Context, io.Writer) error { calls++; return nil })
	router := chi.NewRouter()
	(&Server{}).mountHostRoutes(router)
	for _, fixture := range []struct {
		principal *auth.Principal
		want      int
	}{
		{nil, http.StatusUnauthorized},
		{&auth.Principal{Role: config.RoleViewer}, http.StatusForbidden},
		{&auth.Principal{Role: config.RoleAdmin}, http.StatusOK},
	} {
		before := calls
		req := httptest.NewRequest(http.MethodGet, "/host/updates/upgrade/log", nil)
		if fixture.principal != nil {
			req = req.WithContext(auth.WithPrincipal(req.Context(), fixture.principal))
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != fixture.want || (calls != before) != (fixture.want == http.StatusOK) {
			t.Fatalf("saved-log authorization changed: status=%d calls=%d", w.Code, calls-before)
		}
	}
}

func TestHostAptSavedLogUnreadClientTimesOutThroughLogger(t *testing.T) {
	dir := aptLogDownloadFixture(t, func(_ context.Context, w io.Writer) error {
		chunk := []byte(strings.Repeat("x", 32<<10))
		for range 192 {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
		return nil
	})
	done := make(chan struct{})
	handler := middleware.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		(&Server{}).hostAptUpgradeLog(w, r)
	}))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(aptQuickHTTPWriter{w, 50 * time.Millisecond}, r)
	}))
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetWriteBuffer(4096)
			}
		}
	}
	server.Start()
	defer server.Close()
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1024)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		t.Fatal("unread HTTP client retained log storage/admission")
	}
	assertAPTLogTempCleanup(t, dir, nil)
	if len(aptLogDownloadSlots) != 0 {
		t.Fatal("timed-out HTTP download retained admission")
	}
}

func TestAptSavedLogDeliveryRetainsWriterAndReadFailures(t *testing.T) {
	for _, phase := range []string{"", "deadline", "write", "flush"} {
		failure := errors.New("fixture log delivery failure")
		w := &aptHTTPDeliveryProbe{streamSpy: &streamSpy{}, phase: phase, failure: failure}
		err := deliverAptLog(w, httptest.NewRequest(http.MethodGet, "/", nil), strings.NewReader("log"), 3)
		if phase == "" {
			if err != nil || w.attempts != 1 || w.flushes != 1 || len(w.deadlines) != 2 || !w.deadlines[1].IsZero() {
				t.Fatal("healthy saved log left an armed deadline or retried its response")
			}
		} else if !errors.Is(err, failure) || w.attempts > 1 {
			t.Fatal("saved-log delivery lost its error or retried a failed writer")
		}
	}
	if err := deliverAptLog(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), strings.NewReader("short"), 50); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated spool appeared complete: %v", err)
	}
}

func TestAptSavedLogDeliveryCannotExtendCallerDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	w := &aptHTTPDeliveryProbe{streamSpy: &streamSpy{}}
	err := deliverAptLog(w, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx), strings.NewReader("log"), 3)
	if err != nil || len(w.deadlines) != 2 || !w.deadlines[0].Equal(deadline) || !w.deadlines[1].Equal(deadline) {
		t.Fatal("saved-log writer extended the caller deadline or retained it while idle")
	}
}

func TestHostAptSavedLogFetchWaitAndHTTP2Delivery(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(strconv.FormatBool(http2), func(t *testing.T) {
			dir := aptLogDownloadFixture(t, func(ctx context.Context, w io.Writer) error {
				select {
				case <-time.After(200 * time.Millisecond):
				case <-ctx.Done():
					return ctx.Err()
				}
				_, err := io.WriteString(w, "validated 世🙂\n")
				return err
			})
			done := make(chan struct{})
			handler := middleware.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				(&Server{}).hostAptUpgradeLog(w, r)
			}))
			server := httptest.NewUnstartedServer(handler)
			server.Config.WriteTimeout = 100 * time.Millisecond
			server.EnableHTTP2 = http2
			if http2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "validated 世🙂\n" || (response.ProtoMajor == 2) != http2 || response.ContentLength != int64(len(body)) {
				t.Fatalf("saved log delivery failed after fetch wait: status=%d proto=%s bytes=%d err=%v", response.StatusCode, response.Proto, len(body), err)
			}
			// The last flush can reach the client before server-side defers run.
			// Join the handler before checking close/remove or restoring globals.
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("completed HTTP download did not finish handler cleanup")
			}
			assertAPTLogTempCleanup(t, dir, nil)
		})
	}
}

func TestAptLogSpoolRejectsTheFirstBytePastItsBudget(t *testing.T) {
	var target strings.Builder
	spool := aptLogSpool{w: &target, bytes: hostspec.MaxAPTLogTextBytes - 1}
	if n, err := spool.Write([]byte("a")); n != 1 || err != nil {
		t.Fatal("exact-size spool was rejected")
	}
	if n, err := spool.Write([]byte("b")); n != 0 || err == nil || target.String() != "a" {
		t.Fatal("oversized spool wrote beyond its budget")
	}
}

func TestHostAptSavedLogUnavailableTempNeverCallsWorker(t *testing.T) {
	calls := 0
	dir := aptLogDownloadFixture(t, func(context.Context, io.Writer) error { calls++; return nil })
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, filepath.Join(dir, "missing"))
	}
	w := httptest.NewRecorder()
	(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || calls != 0 || len(aptLogDownloadSlots) != 0 {
		t.Fatal("unavailable private storage called worker or retained admission")
	}
	assertAPTLogTempCleanup(t, dir, nil)
}

func (w *aptLogHTTPProbe) Header() http.Header              { return w.header }
func (w *aptLogHTTPProbe) WriteHeader(code int)             { w.code = code }
func (w *aptLogHTTPProbe) Flush()                           {}
func (w *aptLogHTTPProbe) SetWriteDeadline(time.Time) error { return nil }
func (w *aptLogHTTPProbe) Write(p []byte) (int, error) {
	w.largest = max(w.largest, len(p))
	if len(p) > 64<<10 {
		return 0, io.ErrShortWrite
	}
	w.bytes += len(p)
	return len(p), nil
}

func TestHostAptSavedLogWritesBoundedHTTPChunks(t *testing.T) {
	const size = 4 << 20
	dir, err := os.MkdirTemp(".", ".sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket, err := filepath.Abs(filepath.Join(dir, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var request struct {
			Argv []string `json:"argv"`
		}
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			done <- err
			return
		}
		encoder := json.NewEncoder(conn)
		if len(request.Argv) == 1 && request.Argv[0] == "apt-action-log-stream" {
			for range size / (32 << 10) {
				if err := encoder.Encode(map[string]any{"type": "line", "data": strings.Repeat("x", 32<<10)}); err != nil {
					done <- err
					return
				}
			}
			done <- encoder.Encode(map[string]any{"type": "exit", "code": 0})
			return
		}
		if len(request.Argv) != 1 || request.Argv[0] != "apt-upgrade-log" {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- encoder.Encode(map[string]any{"ok": true, "stdout": strings.Repeat("x", size), "code": 0})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("saved-log wire fixture did not join")
		}
	})
	w := &aptLogHTTPProbe{header: make(http.Header)}
	(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.code != http.StatusOK || w.bytes != size || w.largest > 64<<10 {
		t.Fatalf("whole-log HTTP allocation/write: code=%d bytes=%d largest=%d", w.code, w.bytes, w.largest)
	}
	if w.Header().Get("Content-Length") != strconv.Itoa(size) {
		t.Fatal("download does not declare its validated complete length")
	}
}
