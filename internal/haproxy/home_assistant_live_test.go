// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package haproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/profiles"
	"github.com/easy-waf/easy-waf/internal/testcert"
)

func TestLiveApplicationProfiles(t *testing.T) {
	t.Run("direct", func(t *testing.T) { testLiveApplicationProfiles(t, false) })
	t.Run("with_tls_passthrough", func(t *testing.T) { testLiveApplicationProfiles(t, true) })
}

func testLiveApplicationProfiles(t *testing.T, passthrough bool) {
	t.Helper()
	hx, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not in PATH")
	}
	backend := httptestServer(t)
	defer backend.Close()
	dir := t.TempDir()
	// Keep the chained Unix listener short even when TMPDIR has a long path.
	socketDir, err := os.MkdirTemp("", "ewf-ha-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	settings := config.DefaultSettings(dir)
	settings.SPOEConfigPath = ""
	settings.BlockEmptyUA = false
	settings.WAFBasicRulesEnabled = false
	settings.HAProxyStatsSocketPath = filepath.Join(socketDir, "stats.sock")
	settings.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	settings.RealIPHeader = "X-Real-IP"
	const passthroughMarker = "TLS terminated at the test backend"
	var tlsBackend *httptest.Server
	var passthroughHost string
	if passthrough {
		tlsBackend = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, passthroughMarker)
		}))
		t.Cleanup(tlsBackend.Close)
		names := tlsBackend.Certificate().DNSNames
		if len(names) == 0 {
			t.Fatal("passthrough fixture certificate has no DNS name")
		}
		passthroughHost = names[0]
		addr := tlsBackend.Listener.Addr().(*net.TCPAddr)
		settings.TLSPassthrough = []config.TLSPassthrough{{
			ServerName: passthroughHost, BackendHost: addr.IP.String(), BackendPort: addr.Port, Enabled: true,
		}}
	}
	const clawHost = "openclaw.example.test"
	const clawCert = "openclaw"
	bundle := filepath.Join(dir, "openclaw.pem")
	if err := testcert.WriteBundle(bundle, clawHost); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("load OpenClaw fixture certificate")
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: clawHost, MinVersion: tls.VersionTLS12}
	apps := make([]config.Application, 0, 4)
	for _, profile := range []string{"home-assistant", "balanced", "ha-mcp", "openclaw"} {
		a := config.Application{ID: profile, Name: profile, PublicHost: profile + ".example.test",
			BackendHost: "127.0.0.1", BackendPort: backend.port, Profile: profile,
			Enabled: true, ListenMode: "http_only", WebSocket: true,
			Security: config.ApplicationSecurity{Mode: "balanced", PathACLEnabled: true, MethodFilterEnabled: true}}
		if profile == "ha-mcp" {
			preset := profiles.HAMCPPathPolicy()
			a.PathPolicy = &preset
		}
		if profile == "openclaw" {
			a.ListenMode = "https_only"
			a.CertificateID = clawCert
		}
		apps = append(apps, a)
	}
	crtListPath := filepath.Join(dir, "crt-list.txt")
	rendered, err := Render(RenderInput{Settings: settings, StateDir: dir, Applications: apps, CRTListPath: crtListPath,
		Certificates: map[string]config.Certificate{clawCert: {ID: clawCert, BundlePath: bundle}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crtListPath, []byte(rendered.CRTList), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	tlsPort := freePort(t)
	cfg := strings.ReplaceAll(rendered.HAProxyConfig, "bind *:80", fmt.Sprintf("bind 127.0.0.1:%d", port))
	cfg = strings.ReplaceAll(cfg, "bind *:443", fmt.Sprintf("bind 127.0.0.1:%d", tlsPort))
	cfg = strings.ReplaceAll(cfg, "maxconn 50000", "maxconn 200")
	cfg = stripPrivilegeDrop(cfg)
	// The test HAProxy runs as the current user and owns the Unix listener.
	cfg = strings.ReplaceAll(cfg, "mode 600 user haproxy accept-proxy", "mode 600 accept-proxy")
	// Keep HTTP inactivity short so the later idle WebSocket exchange proves
	// HAProxy switched to its unchanged tunnel timeout after the 101 response.
	httpTimeout := regexp.MustCompile(`(?m)^([\t ]*timeout (client|server))[\t ]+\S+$`)
	cfg = httpTimeout.ReplaceAllString(cfg, "${1} 1s")
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
	for _, clientIP := range []string{"", "192.0.2.42"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/api/forwarded-for", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "home-assistant.example.test"
		if clientIP != "" {
			req.Header.Set("X-Real-IP", clientIP)
			query := req.URL.Query()
			query.Set("client", clientIP)
			req.URL.RawQuery = query.Encode()
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP forwarding for client %q: status %d", clientIP, resp.StatusCode)
		}
	}
	mustStatus(t, client, base+"/.git/config", "home-assistant.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/.env", "home-assistant.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/config/dashboard", "balanced.example.test", "", http.StatusForbidden)
	mustStatus(t, client, base+"/", "ha-mcp.example.test", "", http.StatusNotFound)
	mustStatus(t, client, base+"/api/mcp/assist", "ha-mcp.example.test", "Bearer fixture", http.StatusOK)
	mustStatus(t, client, base+"/api/", "ha-mcp.example.test", "Bearer fixture", http.StatusNotFound)
	clawBase := fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
	clawClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	defer clawClient.CloseIdleConnections()
	mustStatus(t, clawClient, clawBase+"/config", clawHost, "", http.StatusOK)
	mustStatus(t, clawClient, clawBase+"/.env", clawHost, "", http.StatusForbidden)
	proxiedRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, clawBase+"/config/via-proxy", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxiedRequest.Host = clawHost
	proxiedRequest.Header.Set("X-Real-IP", "192.0.2.42")
	proxiedRequest.Header.Set("X-Forwarded-For", "192.0.2.41")
	proxiedRequest.Header.Set("Forwarded", "for=192.0.2.41;proto=https")
	response, err := clawClient.Do(proxiedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("OpenClaw via trusted proxy: HTTP %d, want 200", response.StatusCode)
	}
	if passthrough {
		aliasDialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
		aliasClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig: tlsConfig, DialContext: aliasDialer.DialContext,
		}}
		defer aliasClient.CloseIdleConnections()
		mustStatus(t, aliasClient, clawBase+"/config/via-loopback-alias", clawHost, "", http.StatusOK)

		passthroughRoots := x509.NewCertPool()
		passthroughRoots.AddCert(tlsBackend.Certificate())
		passthroughClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: passthroughRoots, ServerName: passthroughHost, MinVersion: tls.VersionTLS12},
		}}
		defer passthroughClient.CloseIdleConnections()
		resp, err := passthroughClient.Get(clawBase)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || string(body) != passthroughMarker {
			t.Fatalf("TLS passthrough: status %d, response %q, read error %v", resp.StatusCode, body, err)
		}
	}
	mustWebSocketExchange(t, port, "home-assistant.example.test", "/api/websocket", nil, http.StatusSwitchingProtocols)
	mustWebSocketExchange(t, port, "ha-mcp.example.test", "/api/websocket", nil, http.StatusNotFound)
	mustWebSocketExchange(t, tlsPort, clawHost, "/", tlsConfig, http.StatusSwitchingProtocols)
}

// RFC 6455 sections 1.3 and 5.7 supply the fixed handshake and masked Hello
// vectors. This fixture checks transport without a new WebSocket dependency.
const webSocketTestKey = "dGhlIHNhbXBsZSBub25jZQ=="
const webSocketTestAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

var webSocketMaskedHello = []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
var webSocketHello = []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}

func webSocketEchoHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
			r.Header.Get("Sec-WebSocket-Version") != "13" || r.Header.Get("Sec-WebSocket-Key") != webSocketTestKey {
			http.Error(w, "invalid test handshake", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test backend does not support HTTP hijacking")
			http.Error(w, "test backend cannot upgrade", http.StatusInternalServerError)
			return
		}
		connection, stream, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack test WebSocket: %v", err)
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("WebSocket backend deadline: %v", err)
			return
		}
		if _, err := fmt.Fprintf(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketTestAccept); err != nil {
			t.Errorf("WebSocket handshake: %v", err)
			return
		}
		if err := stream.Flush(); err != nil {
			t.Errorf("flush WebSocket handshake: %v", err)
			return
		}
		frame := make([]byte, len(webSocketMaskedHello))
		if _, err := io.ReadFull(stream, frame); err != nil {
			t.Errorf("read masked frame: %v", err)
			return
		}
		if !bytes.Equal(frame, webSocketMaskedHello) {
			t.Errorf("masked frame changed: %x", frame)
			return
		}
		if _, err := connection.Write(webSocketHello); err != nil {
			t.Errorf("echo WebSocket frame: %v", err)
		}
	}
}

func mustWebSocketExchange(t *testing.T, port int, host, path string, tlsConfig *tls.Config, want int) {
	t.Helper()
	dialer := &net.Dialer{Timeout: time.Second}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	var connection net.Conn
	var err error
	if tlsConfig == nil {
		connection, err = dialer.DialContext(t.Context(), "tcp", address)
	} else {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(t.Context(), "tcp", address)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", path, host, webSocketTestKey); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("WebSocket %s: HTTP %d, want %d", host, response.StatusCode, want)
	}
	if want != http.StatusSwitchingProtocols {
		return
	}
	if response.Header.Get("Sec-WebSocket-Accept") != webSocketTestAccept ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") ||
		!strings.EqualFold(response.Header.Get("Connection"), "upgrade") {
		t.Fatalf("invalid WebSocket upgrade headers: %v", response.Header)
	}
	// The ordinary HTTP client/server timeout above is 1s; the tunnel must
	// still carry frames in both directions after a longer quiet interval.
	time.Sleep(1500 * time.Millisecond)
	if _, err := connection.Write(webSocketMaskedHello); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, len(webSocketHello))
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatalf("WebSocket did not survive HTTP idle timeout: %v", err)
	}
	if !bytes.Equal(frame, webSocketHello) {
		t.Fatalf("WebSocket echo changed: %x", frame)
	}
}
