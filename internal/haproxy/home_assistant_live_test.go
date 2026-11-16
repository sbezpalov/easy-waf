// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package haproxy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

func TestLiveHomeAssistantPublication(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH")
	}
	backend := httptestServer(t)
	defer backend.Close()
	dir := t.TempDir()
	socket, err := os.CreateTemp("/tmp", "ewf-ha-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socketPath := socket.Name()
	_ = socket.Close()
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	settings := config.DefaultSettings(dir)
	settings.SPOEConfigPath = ""
	settings.BlockEmptyUA = false
	settings.WAFBasicRulesEnabled = false
	settings.HAProxyStatsSocketPath = socketPath
	var apps []config.Application
	for _, profile := range []string{"home-assistant", "balanced", "ha-mcp"} {
		a := config.Application{ID: profile, Name: profile, PublicHost: profile + ".example.test",
			BackendHost: "127.0.0.1", BackendPort: backend.port, Profile: profile,
			Enabled: true, ListenMode: "http_only", WebSocket: true,
			Security: config.ApplicationSecurity{Mode: "balanced", PathACLEnabled: true, MethodFilterEnabled: true}}
		if profile == "ha-mcp" {
			preset := profiles.HAMCPPathPolicy()
			a.PathPolicy = &preset
		}
		apps = append(apps, a)
	}
	rendered, err := Render(RenderInput{Settings: settings, StateDir: dir, Applications: apps})
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cfg := strings.ReplaceAll(rendered.HAProxyConfig, "bind *:80", fmt.Sprintf("bind 127.0.0.1:%d", port))
	cfg = strings.ReplaceAll(cfg, "maxconn 50000", "maxconn 200")
	cfg = stripPrivilegeDrop(cfg)
	path := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, hx, "-db", "-f", path)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port))
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 3 * time.Second}
	for _, route := range []string{"/", "/config/dashboard", "/api/", "/api/websocket"} {
		mustStatus(t, client, base+route, "home-assistant.example.test", "", http.StatusOK)
	}
	mustStatus(t, client, base+"/.git/config", "home-assistant.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/.env", "home-assistant.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/config/dashboard", "balanced.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/", "ha-mcp.example.test", "", http.StatusNotFound)
	mustStatus(t, client, base+"/api/mcp/assist", "ha-mcp.example.test", "Bearer fixture", http.StatusOK)
	mustStatus(t, client, base+"/api/", "ha-mcp.example.test", "Bearer fixture", http.StatusNotFound)
}
