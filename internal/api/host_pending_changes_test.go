// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

func pendingChangesWireFixture(t *testing.T, payload string, code int) {
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
		var request struct {
			Argv []string `json:"argv"`
		}
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			done <- err
			return
		}
		if len(request.Argv) != 1 || request.Argv[0] != "rollback-status" {
			done <- errors.New("pending status invoked another opcode")
			return
		}
		done <- json.NewEncoder(conn).Encode(map[string]any{"ok": code == 0, "stdout": payload, "code": code})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("pending status fixture did not join")
		}
	})
}

func TestHostPendingChangesMapsFirewallAndNeverReturnsToken(t *testing.T) {
	const operationID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pendingChangesWireFixture(t, `{"changes":[{"operation_id":"`+operationID+`","kind":"nft","phase":"pending","expires_at":"2030-01-02T03:04:05Z","confirmable":true}]}`, 0)
	rec := httptest.NewRecorder()
	(&Server{}).hostGetPendingChanges(rec, httptest.NewRequest(http.MethodGet, "/api/v1/host/changes/pending", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"kind":"firewall"`) || !strings.Contains(body, operationID) || strings.Contains(body, `"token"`) {
		t.Fatalf("unsafe or incomplete response: %s", body)
	}
}

func TestHostPendingChangesRejectsAmbiguousBrokerState(t *testing.T) {
	const operationID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pendingChangesWireFixture(t, `{"changes":[{"operation_id":"`+operationID+`","kind":"nft","phase":"expired","confirmable":true}]}`, 0)
	rec := httptest.NewRecorder()
	(&Server{}).hostGetPendingChanges(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), operationID) {
		t.Fatalf("unverified state exposed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostPendingChangesReportsBusyWithRetryHint(t *testing.T) {
	pendingChangesWireFixture(t, "", hostspec.RollbackStatusBusyCode)
	rec := httptest.NewRecorder()
	(&Server{}).hostGetPendingChanges(rec, httptest.NewRequest(http.MethodGet, "/api/v1/host/changes/pending", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" ||
		rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), `"changes"`) {
		t.Fatalf("invalid busy response: %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
}
