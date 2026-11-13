// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func aptEventWireFixture(t *testing.T, argv []string, wire string) {
	t.Helper()
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
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var request struct{ Argv []string }
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			done <- err
			return
		}
		if !slices.Equal(request.Argv, argv) {
			done <- errors.New("event handler invoked an unexpected/mutating opcode")
			return
		}
		_, err = io.WriteString(conn, wire)
		done <- err
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("event wire fixture did not join")
		}
	})
}

func TestHostAptAmbiguousEventsNeverBecomeSuccessfulDownloadsOrObservation(t *testing.T) {
	for _, event := range []string{
		`{"type":"exit","code":100,"Code":0}`,
		`{"type":"exit","code":100,"code":0}`,
		`{"type":"exit","code":0,"error":null}`,
		`{"Type":"exit","Code":0}`,
	} {
		for _, download := range []bool{true, false} {
			name := "observe/"
			if download {
				name = "download/"
			}
			t.Run(name+event, func(t *testing.T) {
				dir := ""
				if download {
					dir = aptLogDownloadFixture(t, downloadAPTLogFn)
				}
				args := []string{"apt-action-attach-stream", aptObserveTestID}
				if download {
					args = []string{"apt-action-log-stream"}
				}
				aptEventWireFixture(t, args, "{\"type\":\"line\",\"data\":\"private saved output\"}\n"+event+"\n")
				w := httptest.NewRecorder()
				if download {
					(&Server{}).hostAptUpgradeLog(w, httptest.NewRequest(http.MethodGet, "/", nil))
					if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private") {
						t.Fatalf("ambiguous saved-log result became successful/public: code=%d", w.Code)
					}
					assertAPTLogTempCleanup(t, dir, nil)
					if len(aptLogDownloadSlots) != 0 {
						t.Fatal("rejected protocol retained download admission")
					}
					return
				}
				(&Server{}).hostAptAttachStream(w, httptest.NewRequest(http.MethodPost, "/?run_id="+aptObserveTestID, nil))
				lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
				var last struct {
					Type  string
					Code  int
					Error string
				}
				if json.Unmarshal([]byte(lines[len(lines)-1]), &last) != nil || last.Type != "exit" || last.Code != -1 || last.Error == "" || strings.Contains(w.Body.String(), event) {
					t.Fatalf("ambiguous event was relayed/reported as completion: %s", w.Body.String())
				}
			})
		}
	}
}
