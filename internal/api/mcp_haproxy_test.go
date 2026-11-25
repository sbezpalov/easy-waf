// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestMCPHAProxyCheckSocket(t *testing.T) {
	const sample = "# pxname,svname,status,type,check_status\n" +
		"private_frontend,FRONTEND,OPEN,0,\n" +
		"another_frontend,FRONTEND,STOP,0,\n" +
		"full_frontend,FRONTEND,FULL,0,\n" +
		"private_backend,BACKEND,UP,1,\n" +
		"private_backend,private_server,UP,2,L7OK\n" +
		"private_backend,another_server,DOWN,2,L4CON\n" +
		"down_backend,BACKEND,DOWN,1,\n" +
		"healthy_backend,BACKEND,UP,1,\n" +
		"healthy_backend,healthy_server,UP,2,L7OK\n" +
		"unknown_backend,BACKEND,UP,1,\n" +
		"unknown_backend,unknown_server,UP,2,INI\n"
	const unavailable = `{"state":"unavailable"}`
	dir, err := os.MkdirTemp(".", ".mcp-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path, err := filepath.Abs(filepath.Join(dir, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("m", 40)
	t.Setenv("EASY_WAF_MCP_API_TOKEN", secret)
	call := func(s *Server, resource string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/mcp/diagnostics/"+resource, nil)
		r.RemoteAddr = "127.0.0.1:31000"
		if authorized {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		return w
	}
	token := auth.LoadMCPAPIToken(nil)
	server := &Server{Eng: engine.New(dir, nil, config.GlobalSettings{HAProxyStatsSocketPath: path}), MCPAPIToken: token}
	if w := call(server, "haproxy", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if w := call(server, "haproxy?socket=ignored", true); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if w := call(server, "haproxy", true); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != unavailable {
		t.Fatalf("missing socket response: %d %s", w.Code, w.Body)
	}

	for i, tc := range []struct {
		name, sample string
		want         []string
	}{
		{"invalid sample", "private_socket_error\n", []string{unavailable}},
		{"runtime states", sample, []string{
			`"state":"available"`, `"collected_at":`, `"frontends":{"open":1,"full":1,"stopped":1,"unknown":0}`,
			`"backends":{"healthy":1,"degraded":1,"down":1,"unknown":1}`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(filepath.Dir(path), fmt.Sprintf("%d.sock", i))
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					finished <- err
					return
				}
				command, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					if command != "show stat\n" {
						err = fmt.Errorf("unexpected stats command %q", command)
					} else {
						_, err = io.WriteString(conn, tc.sample)
					}
				}
				finished <- err
			}()
			server := &Server{Eng: engine.New(dir, nil, config.GlobalSettings{HAProxyStatsSocketPath: socket}), MCPAPIToken: token}
			w := call(server, "haproxy", true)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			body := w.Body.String()
			if w.Code != http.StatusOK || strings.Contains(body, "private_") || strings.Contains(body, ".sock") {
				t.Fatalf("unexpected response: %d %s", w.Code, body)
			}
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("response %s missing %s", body, want)
				}
			}
			w = call(server, "doctor", true)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(),
				`"database":"not configured","edge_configuration":"unavailable","haproxy":`+strings.TrimSpace(body)) {
				t.Fatalf("doctor did not retain runtime check without database: %d %s", w.Code, w.Body)
			}
		})
	}
}
