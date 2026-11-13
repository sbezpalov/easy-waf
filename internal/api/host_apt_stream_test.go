// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestHostAptUpgradeStream_requiresXHR(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/upgrade/stream", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	RequireXHR(http.HandlerFunc(s.hostAptUpgradeStream)).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHostAptUpgradeStream_setsNDJSONContentType(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/upgrade/stream", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.hostAptUpgradeStream(w, req)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/x-ndjson") {
		t.Fatalf("content-type %q", ct)
	}
	if w.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatal("expected X-Accel-Buffering: no")
	}
	if w.Header().Get("Content-Encoding") != "identity" {
		t.Fatal("expected Content-Encoding: identity")
	}
}

type streamSpy struct {
	header  http.Header
	chunks  [][]byte
	flushes int
}

func (s *streamSpy) Header() http.Header {
	if s.header == nil {
		s.header = make(http.Header)
	}
	return s.header
}

func (s *streamSpy) Write(p []byte) (int, error) {
	s.chunks = append(s.chunks, append([]byte(nil), p...))
	return len(p), nil
}

func (s *streamSpy) WriteHeader(statusCode int) {
	s.Header().Set("X-Status", http.StatusText(statusCode))
}

func (s *streamSpy) Flush() {
	s.flushes++
}

func TestHostAptUpgradeStream_flushesIncrementally(t *testing.T) {
	orig := privilegedStreamFn
	defer func() { privilegedStreamFn = orig }()

	privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, _ ...string) error {
		for _, l := range []string{
			`{"type":"line","data":"line-a"}`,
			`{"type":"line","data":"line-b"}`,
			`{"type":"exit","code":0}`,
		} {
			if err := onLine([]byte(l)); err != nil {
				return err
			}
		}
		return nil
	}

	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/upgrade/stream", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"

	w := &streamSpy{}
	s.hostAptUpgradeStream(w, req)

	if w.flushes < 2 {
		t.Fatalf("flushes=%d chunks=%d", w.flushes, len(w.chunks))
	}
	body := strings.Join(func() []string {
		out := make([]string, len(w.chunks))
		for i, c := range w.chunks {
			out[i] = string(c)
		}
		return out
	}(), "")
	sc := bufio.NewScanner(strings.NewReader(body))
	var n int
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal([]byte(sc.Text()), &m) == nil {
			n++
		}
	}
	if n < 3 {
		t.Fatalf("expected 3 ndjson records, got %d body=%q", n, body)
	}
}

func TestHostAutoremoveStream_requiresXHR(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/autoremove/stream", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	RequireXHR(http.HandlerFunc(s.hostAutoremoveStream)).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHostAutoremoveStream_setsNDJSONContentType(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/autoremove/stream", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.hostAutoremoveStream(w, req)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/x-ndjson") {
		t.Fatalf("content-type %q", ct)
	}
}

func TestHostAutoremoveStream_flushesIncrementally(t *testing.T) {
	orig := privilegedStreamFn
	defer func() { privilegedStreamFn = orig }()

	privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, argv ...string) error {
		if len(argv) != 1 || argv[0] != "apt-autoremove-stream" {
			t.Fatalf("argv: %v", argv)
		}
		for _, l := range []string{
			`{"type":"line","data":"removing foo"}`,
			`{"type":"exit","code":0}`,
		} {
			if err := onLine([]byte(l)); err != nil {
				return err
			}
		}
		return nil
	}

	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/autoremove/stream", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"

	w := &streamSpy{}
	s.hostAutoremoveStream(w, req)
	if w.flushes < 1 {
		t.Fatalf("flushes=%d", w.flushes)
	}
}

func TestHostAptStreamRejectsMissingCompletion(t *testing.T) {
	for _, op := range []string{"apt-upgrade-stream", "apt-autoremove-stream"} {
		t.Run(op, func(t *testing.T) {
			previous := privilegedStreamFn
			t.Cleanup(func() { privilegedStreamFn = previous })
			privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, _ ...string) error {
				return onLine([]byte(`{"type":"line","data":"working"}`))
			}
			eng := engine.New("", nil, config.GlobalSettings{})
			s := &Server{Eng: eng}
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			recorder := httptest.NewRecorder()
			s.streamAptAction(recorder, req, op, "started", "done")
			var terminal struct {
				Type  string `json:"type"`
				Code  int    `json:"code"`
				Error string `json:"error"`
			}
			lines := strings.Split(strings.TrimSpace(recorder.Body.String()), "\n")
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &terminal); err != nil {
				t.Fatal(err)
			}
			if terminal.Type != "exit" || terminal.Code != -1 || terminal.Error == "" {
				t.Fatalf("missing exit was treated as successful completion: %s", recorder.Body.String())
			}
		})
	}
}
