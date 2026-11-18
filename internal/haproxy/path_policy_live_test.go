// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package haproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/geoip"
)

func TestLivePublicationRules(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH")
	}
	backend := httptestServer(t)
	defer backend.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	settings := config.DefaultSettings(dir)
	socket, err := os.CreateTemp("/tmp", "ew-rules*.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socket.Name()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(socket.Name()) })
	settings.HAProxyStatsSocketPath = socket.Name()
	settings.SPOEConfigPath = ""
	app := config.Application{
		ID: "live-rules", PublicHost: "rules.example.test", Enabled: true, ListenMode: "http_only",
		BackendHost: "127.0.0.1", BackendPort: backend.port, Profile: "balanced",
		RestrictedPaths: []config.RestrictedPath{{PathPrefix: "/api/health/private", AllowedCIDRs: []string{"192.0.2.0/24"}}},
		PolicyRules: []config.PublicationRule{
			{ID: "watch-api", Action: config.RuleCount, Match: config.PublicationMatch{PathPrefix: "/api/"}},
			{ID: "watch-client", Action: config.RuleCount, Match: config.PublicationMatch{
				PathPrefix: "/api", Methods: []string{"GET", "HEAD"}, SourceCIDRs: []string{"127.0.0.0/8", "::1"},
				Header: "User-Agent", HeaderPrefix: "-i",
			}},
			{ID: "pass-health", Action: config.RulePass, Match: config.PublicationMatch{PathPrefix: "/api/health"}},
			{ID: "deny-api", Action: config.RuleBlock, Match: config.PublicationMatch{PathPrefix: "/api"}},
			{ID: "watch-status", Action: config.RuleCount, Match: config.PublicationMatch{PathPrefix: "/status"}},
		},
	}
	wide := app
	wide.ID = "wide-rules"
	wide.PublicHost = strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61)
	wide.RestrictedPaths = []config.RestrictedPath{{PathPrefix: "/blocked", AllowedCIDRs: []string{"192.0.2.0/24"}}}
	wide.PolicyRules = make([]config.PublicationRule, config.MaxPublicationRules)
	for i := range wide.PolicyRules {
		wide.PolicyRules[i] = config.PublicationRule{
			ID: fmt.Sprintf("rule-%027d", i), Action: config.RuleCount, Match: config.PublicationMatch{PathPrefix: "/"},
		}
	}
	rendered, err := Render(RenderInput{Settings: settings, StateDir: dir, Applications: []config.Application{app, wide}})
	if err != nil {
		t.Fatal(err)
	}
	edge := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := strings.ReplaceAll(rendered.HAProxyConfig, "bind *:80", "bind "+edge)
	cfg = stripPrivilegeDrop(strings.ReplaceAll(cfg, "maxconn 50000", "maxconn 200"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(hx, "-c", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("HAProxy config check: %v\n%s", err, out)
	}
	logFile, err := os.Create(filepath.Join(dir, "edge.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(hx, "-f", cfgPath, "-db")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	waitTCP(t, edge)

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	mustStatus(t, client, "http://"+edge+"/?q="+strings.Repeat("a", 3000), wide.PublicHost, "", 200)
	mustStatus(t, client, "http://"+edge+"/blocked/"+strings.Repeat("a", 3000), wide.PublicHost, "", 403)
	for _, tc := range []struct {
		path, method, ua string
		status           int
	}{
		{"/api/health", "GET", "-i Example Client", 200},
		{"/api/health/private", "GET", "-i Example Client", 403},
		{"/api?token=fixture", "GET", "-i Example Client", 403},
		{"/api/job", "POST", "-i Example Client", 403},
		{"/api/job", "GET", "Other Client", 403},
		{"/status", "GET", "-i Example Client", 200},
		{"/apiary", "GET", "-i Example Client", 200},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://"+edge+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = app.PublicHost
		req.Header.Set("User-Agent", tc.ua)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s %s: got %d, want %d", tc.method, tc.path, resp.StatusCode, tc.status)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	var raw []byte
	for {
		raw, err = os.ReadFile(logFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "GET /apiary") || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var journal strings.Builder
	encoder := json.NewEncoder(&journal)
	blockedGrep := regexp.MustCompile(blocklog.JournalGrepBlocked)
	policyGrep := regexp.MustCompile(blocklog.JournalGrepPolicy)
	var blockedLines, policyLines int
	for _, line := range strings.Split(string(raw), "\n") {
		if blockedGrep.MatchString(line) {
			blockedLines++
		}
		if policyGrep.MatchString(line) {
			policyLines++
		}
		if err := encoder.Encode(map[string]string{"MESSAGE": line}); err != nil {
			t.Fatal(err)
		}
	}
	events, _ := blocklog.ParseRuleJournal(strings.NewReader(journal.String()))
	blocks, _ := blocklog.ParseJournal(strings.NewReader(journal.String()))
	if blockedLines != len(blocks) || policyLines != len(events) {
		t.Fatalf("journal grep and parsers disagree: blocked %d/%d, policy %d/%d", blockedLines, len(blocks), policyLines, len(events))
	}
	if len(blocks) == 0 || blocks[0].Host != wide.PublicHost || blocks[0].Status != 403 ||
		!strings.HasPrefix(blocks[0].Path, "/blocked/") || !strings.HasSuffix(blocks[0].Path, "…") {
		t.Fatalf("blocked request with long path missing from journal: %+v", blocks)
	}
	if len(blocks) < 3 || blocks[2].Rule != "policy_block" || blocks[2].Path != "/api" {
		t.Fatalf("journal should return only the blocked request path: %+v", blocks)
	}
	if len(events) == 0 || events[0].Host != wide.PublicHost || events[0].Status != 200 || len(events[0].Matches) != len(wide.PolicyRules) {
		t.Fatal("journal lost the full hostname or rule list at the supported limits")
	}
	for i, match := range events[0].Matches {
		if match.ID != wide.PolicyRules[i].ID || match.Action != config.RuleCount {
			t.Fatalf("rule %d in the journal: %+v", i, match)
		}
	}
	if len(events) < 2 || events[1].Host != wide.PublicHost || events[1].Status != 403 || len(events[1].Matches) != len(wide.PolicyRules) {
		t.Fatal("journal lost the rule list for the blocked request at the supported limits")
	}
	events = events[2:]
	want := []string{"200 watch-api watch-client pass-health", "403 watch-api watch-client pass-health",
		"403 watch-api watch-client deny-api", "403 watch-api deny-api",
		"403 watch-api deny-api", "200 watch-status"}
	if len(events) != len(want) {
		t.Fatalf("got %d rule events, want %d; live HAProxy log:\n%s", len(events), len(want), raw)
	}
	for i, event := range events {
		got := fmt.Sprint(event.Status)
		for _, match := range event.Matches {
			got += " " + match.ID
		}
		if got != want[i] || event.Host != app.PublicHost {
			t.Fatalf("event %d: %+v, want %q on %s", i, event, want[i], app.PublicHost)
		}
	}
}

func TestLiveGeoIPPolicy(t *testing.T) {
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH")
	}
	backend := httptestServer(t)
	defer backend.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	sock, err := os.CreateTemp("/tmp", "ew-geo*.sock")
	if err != nil {
		t.Fatal(err)
	}
	_ = sock.Close()
	_ = os.Remove(sock.Name())
	t.Cleanup(func() { _ = os.Remove(sock.Name()) })
	settings := config.DefaultSettings(dir)
	settings.HAProxyStatsSocketPath = sock.Name()
	settings.SPOEConfigPath = ""
	var apps []config.Application
	for _, policy := range []string{"allow", "deny"} {
		app := config.Application{
			ID: policy, PublicHost: policy + ".example.test", Enabled: true, ListenMode: "http_only",
			BackendHost: "127.0.0.1", BackendPort: backend.port, Profile: "balanced",
			Security: config.ApplicationSecurity{Mode: "custom", GeoIPEnabled: true, GeoIPPolicy: policy, GeoIPCountryList: []string{"NL"}},
		}
		if err := geoip.WriteAppEnforceMap(map[string][]string{"NL": {"127.0.0.2/32", "::1/128"}},
			app.Security.GeoIPCountryList, geoip.AppEnforceMapPath(dir, app.ID)); err != nil {
			t.Fatal(err)
		}
		apps = append(apps, app)
	}
	rendered, err := Render(RenderInput{Settings: settings, StateDir: dir, Applications: apps})
	if err != nil {
		t.Fatal(err)
	}
	edgePort := freePort(t)
	edge4 := fmt.Sprintf("127.0.0.1:%d", edgePort)
	edge6 := fmt.Sprintf("[::1]:%d", edgePort)
	binds := "bind " + edge4 + "\n\tbind " + edge6
	cfg := strings.ReplaceAll(rendered.HAProxyConfig, "bind *:80", binds)
	cfg = stripPrivilegeDrop(strings.ReplaceAll(cfg, "maxconn 50000", "maxconn 200"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(hx, "-f", cfgPath, "-db")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	waitTCP(t, edge4)
	for _, tc := range []struct {
		name, source, address string
		allow, deny           int
	}{
		{"selected IPv4", "127.0.0.2", edge4, 200, 403},
		{"unknown IPv4", "127.0.0.1", edge4, 403, 200},
		{"selected IPv6", "::1", edge6, 200, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.source)}}
			transport := &http.Transport{DialContext: dialer.DialContext}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			base := "http://" + tc.address + "/"
			mustStatus(t, client, base, "allow.example.test", "", tc.allow)
			mustStatus(t, client, base, "deny.example.test", "", tc.deny)
		})
	}
}

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
	mux.HandleFunc("/api/websocket", webSocketEchoHandler(t))
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
	ws := webSocketEchoHandler(t)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "openclaw.example.test" {
			want := "127.0.0.1"
			if r.URL.Path == "/config/via-proxy" {
				want = "192.0.2.42"
			}
			forwarded := r.Header.Values("X-Forwarded-For")
			if len(forwarded) != 1 || forwarded[0] != want ||
				r.Header.Get("X-Real-IP") != "" || r.Header.Get("Forwarded") != "" ||
				r.Header.Get("X-Forwarded-Proto") != "https" {
				t.Errorf("unexpected OpenClaw forwarding metadata: %q", forwarded)
				http.Error(w, "invalid forwarding metadata", http.StatusBadRequest)
				return
			}
			ws(w, r)
			return
		}
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
