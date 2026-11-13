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
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
)

func aptStatusWireFixture(t *testing.T, payload string, ok bool) {
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
		var request struct {
			Argv []string `json:"argv"`
		}
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			done <- err
			return
		}
		if len(request.Argv) != 1 || request.Argv[0] != "apt-upgrade-status" {
			done <- errors.New("status request invoked another opcode")
			return
		}
		code, message := 0, ""
		if !ok {
			code, message = 1, "private broker error"
		}
		done <- json.NewEncoder(conn).Encode(map[string]any{"ok": ok, "stdout": payload, "code": code, "error": message})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("status fixture did not join")
		}
	})
}

func TestHostAptStatusRejectsUnverifiedUpstreamPayload(t *testing.T) {
	for _, payload := range []string{
		"", " ", "private corrupt response", "null", "[]", "false", "{}",
		`{"active":null}`, `{"active":"false"}`, `{"active":0}`,
		`{"Active":false}`, `{"ACTIVE":true}`, `{"active":null,"Active":false}`,
		`{"active":false,"error":null,"Error":""}`,
		`{"active":true`, `{"active":false} {"active":true}`,
		`{"active":true,"active":false}`, `{"active":false,"error":null}`,
		`{"active":false,"exit_code":"0"}`, `{"active":false,"exit_code":0.5}`,
		`{"active":false,"exit_code":null}`, `{"active":false,"stream":1}`,
		`{"active":true,"run_id":[]}`, `{"active":true,"action":{}}`,
		`{"active":false,"padding":"` + strings.Repeat("x", 64<<10) + `"}`,
	} {
		t.Run(strings.ReplaceAll(payload[:min(len(payload), 35)], "\n", " "), func(t *testing.T) {
			aptStatusWireFixture(t, payload, true)
			w := httptest.NewRecorder()
			(&Server{}).hostAptUpgradeStatus(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "active") || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("unverified payload became success/idle or leaked data: status=%d body_prefix=%q", w.Code, w.Body.String()[:min(w.Body.Len(), 120)])
			}
		})
	}
}

func TestHostAptStatusPreservesCurrentLegacyAndUnknownOutcomes(t *testing.T) {
	for _, payload := range []string{
		`{"active":false}`,
		`{"active":true,"exit_code":0,"error":""}`,
		`{"active":false,"exit_code":100,"error":""}`,
		`{"active":false,"exit_code":-1,"error":"previous outcome unknown"}`,
		`{"active":true,"exit_code":-1,"error":"cannot verify process","run_id":"0123456789abcdef0123456789abcdef"}`,
		`{"active":true,"exit_code":0,"error":"","action":"clean","stream":false,"run_id":"0123456789abcdef0123456789abcdef","future_counter":9007199254740993}`,
	} {
		t.Run(payload[:min(len(payload), 40)], func(t *testing.T) {
			aptStatusWireFixture(t, payload, true)
			w := httptest.NewRecorder()
			(&Server{}).hostAptUpgradeStatus(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("valid older/current status rejected: %d", w.Code)
			}
			var got, want map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(payload), &want); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatal("status invented fields or discarded forward-compatible metadata")
			}
			for key, value := range want {
				if string(got[key]) != string(value) {
					t.Fatalf("status field %s changed: %s -> %s", key, value, got[key])
				}
			}
		})
	}
}

func TestHostAptStatusRequiresAdminWithoutMutationStepUp(t *testing.T) {
	router := chi.NewRouter()
	(&Server{}).mountHostRoutes(router)
	for _, fixture := range []struct {
		principal *auth.Principal
		want      int
	}{
		{nil, http.StatusUnauthorized},
		{&auth.Principal{Role: config.RoleViewer}, http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/host/updates/upgrade/status", nil)
		if fixture.principal != nil {
			req = req.WithContext(auth.WithPrincipal(req.Context(), fixture.principal))
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != fixture.want {
			t.Fatalf("status auth boundary changed: %d", w.Code)
		}
	}
	aptStatusWireFixture(t, `{"active":false}`, true)
	req := httptest.NewRequest(http.MethodGet, "/host/updates/upgrade/status", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{Role: config.RoleAdmin}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read-only admin status required mutation step-up: %d", w.Code)
	}
}

func TestHostAptStatusAcceptsExactSizeBoundary(t *testing.T) {
	prefix, suffix := `{"active":false,"padding":"`, `"}`
	payload := prefix + strings.Repeat("x", (64<<10)-len(prefix)-len(suffix)) + suffix
	if _, err := decodeAPTStatus([]byte(payload)); err != nil {
		t.Fatalf("exactly64 KiB status was rejected: %v", err)
	}
}

func TestHostAptStatusTransportFailureNeverBecomesInactive(t *testing.T) {
	aptStatusWireFixture(t, "private partial response", false)
	w := httptest.NewRecorder()
	(&Server{}).hostAptUpgradeStatus(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "active") || strings.Contains(w.Body.String(), "private") {
		t.Fatal("broker failure became inactive status or leaked detail")
	}
	var value map[string]any
	if err := json.NewDecoder(w.Body).Decode(&value); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func FuzzDecodeAPTStatus(f *testing.F) {
	for _, seed := range []string{
		`{"active":false}`, `{"active":true,"exit_code":0,"error":""}`,
		`{"active":null,"Active":false}`, `{"Active":false}`, `null`,
		`{"active":true,"active":false}`, `{"active":false,"counter":9007199254740993}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		fields, err := decodeAPTStatus(payload)
		if err != nil {
			return
		}
		var active *bool
		if len(payload) > 64<<10 || json.Unmarshal(fields["active"], &active) != nil || active == nil {
			t.Fatal("accepted status has no verified active boolean or exceeds its budget")
		}
		encoded, err := json.Marshal(fields)
		if err != nil || !json.Valid(encoded) {
			t.Fatal("accepted status cannot be forwarded as a valid JSON object")
		}
	})
}
