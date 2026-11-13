// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package haproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// TestLivePathPolicy exercises allowlist, the Authorization requirement and an
// SSE stream that stays open for more than a minute. The generated client
// timeout is 70s; the frontend default is 50s, so a stream that is still alive
// after 62s of silence shows the per-path timeout is in effect.
func TestLivePathPolicy(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH")
	}
	backend := httptestServer(t)
	defer backend.Close()

	edgePort := freePort(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	sockFile, err := os.CreateTemp("/tmp", "ew*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sock := sockFile.Name()
	_ = sockFile.Close()
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	settings := config.DefaultSettings(dir)
	settings.SPOEConfigPath = ""
	settings.BlockEmptyUA = false
	settings.WAFBasicRulesEnabled = false
	settings.HAProxyStatsSocketPath = sock
	app := config.Application{
		ID:          "live1",
		Name:        "Live",
		PublicHost:  "mcp.example.com",
		BackendHost: "127.0.0.1",
		BackendPort: backend.port,
		Profile:     "ha-mcp",
		Enabled:     true,
		ListenMode:  "http_only",
		Security: config.ApplicationSecurity{
			Mode:                 "balanced",
			RateLimitEnabled:     true,
			PathACLEnabled:       true,
			MethodFilterEnabled:  true,
			BasicWAFEnabled:      false,
			BotProtectionEnabled: false,
			CrowdSecEnabled:      false,
		},
		PathPolicy: &config.PathPolicy{
			Mode: config.PathModeAllowlist,
			Allow: []string{
				"/api/mcp",
				"/mcp_server/sse",
				"/auth",
				"/.well-known/oauth-authorization-server",
				"/.git",
			},
			Rules: []config.PathRule{
				{PathPrefix: "/api/mcp", RequireHeader: "Authorization", RequireValuePrefix: "Bearer ", RatePer10s: 50},
				{PathPrefix: "/mcp_server/sse", ClientTimeoutSec: 70, ServerTimeoutSec: 70, RatePer10s: 20},
			},
		},
	}
	got, err := Render(RenderInput{Settings: settings, StateDir: dir, Applications: []config.Application{app}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := got.HAProxyConfig
	cfg = strings.ReplaceAll(cfg, "bind *:80", fmt.Sprintf("bind 127.0.0.1:%d", edgePort))
	// GitHub's container cannot raise the FD limit high enough for maxconn 50000.
	cfg = strings.ReplaceAll(cfg, "maxconn 50000", "maxconn 200")
	cfg = stripPrivilegeDrop(cfg)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(hx, "-f", cfgPath, "-db")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	base := fmt.Sprintf("http://127.0.0.1:%d", edgePort)
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", edgePort))

	client := &http.Client{Timeout: 5 * time.Second}
	mustStatus(t, client, base+"/api/mcp", "mcp.example.com", "", http.StatusUnauthorized)
	mustStatus(t, client, base+"/api/mcp", "mcp.example.com", "Bearer test-token", http.StatusOK)
	mustStatus(t, client, base+"/not-published", "mcp.example.com", "", http.StatusNotFound)
	mustStatus(t, client, base+"/.git/config", "mcp.example.com", "", http.StatusForbidden)

	sseClient := &http.Client{Timeout: 80 * time.Second}
	req, err := http.NewRequest(http.MethodGet, base+"/mcp_server/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "mcp.example.com"
	resp, err := sseClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sse status %d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first, "hi") {
		t.Fatalf("first event %q", first)
	}
	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("sse closed during a 62s idle (client timeout did not move): %v", err)
	}
	if !strings.Contains(second, "still") {
		t.Fatalf("second event %q", second)
	}
}

type testBackend struct {
	port int
	srv  *http.Server
}

func (b *testBackend) Close() {
	_ = b.srv.Close()
}

func httptestServer(t *testing.T) *testBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/mcp_server/sse", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		fmt.Fprintln(w, "data: hi")
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(62 * time.Second)
		fmt.Fprintln(w, "data: still")
		if flusher != nil {
			flusher.Flush()
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return &testBackend{port: ln.Addr().(*net.TCPAddr).Port, srv: srv}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("haproxy did not listen on %s", addr)
}

func mustStatus(t *testing.T, client *http.Client, url, host, auth string, want int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", url, auth, resp.StatusCode, want)
	}
}

func stripPrivilegeDrop(cfg string) string {
	var b strings.Builder
	for _, line := range strings.Split(cfg, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "user haproxy" || trim == "group haproxy" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
