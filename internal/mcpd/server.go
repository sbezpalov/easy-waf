// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mcpd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/easy-waf/easy-waf"
	"github.com/easy-waf/easy-waf/internal/auth"
)

const (
	protocolVersion = "2025-11-25"
	diagnosticsPath = "/api/v1/mcp/diagnostics"
	maxAPIResponse  = 1 << 20
)

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func (c apiClient) read(ctx context.Context, path string, query url.Values) *mcp.CallToolResult {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+diagnosticsPath+path, nil)
	if err != nil {
		return diagnosticFailure("invalid_request", 0)
	}
	r.URL.RawQuery = query.Encode()
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return diagnosticFailure(diagnosticTransportCode(err, "api_unreachable"), 0)
	}
	defer resp.Body.Close()
	unready := path == "/ready" && resp.StatusCode == http.StatusServiceUnavailable
	if !unready && resp.StatusCode != http.StatusOK {
		return diagnosticFailure(diagnosticHTTPCode(resp.StatusCode), resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return diagnosticFailure(diagnosticTransportCode(err, "api_read_failed"), 0)
	}
	if len(body) > maxAPIResponse || !json.Valid(body) {
		return diagnosticFailure("invalid_api_response", 0)
	}
	return &mcp.CallToolResult{IsError: unready, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}
}

func diagnosticFailure(code string, status int) *mcp.CallToolResult {
	// Codes come from this package. Never include error strings, request URLs,
	// response headers or response bodies from an unsuccessful API call.
	text := fmt.Sprintf(`{"code":%q}`, code)
	if status != 0 {
		text = fmt.Sprintf(`{"code":%q,"http_status":%d}`, code, status)
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func diagnosticTransportCode(err error, fallback string) string {
	var verify *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "request_canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "api_timeout"
	case errors.As(err, &verify):
		return "api_certificate_rejected"
	default:
		return fallback
	}
}

func diagnosticHTTPCode(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "api_token_rejected"
	case status == http.StatusForbidden:
		return "api_access_forbidden"
	case status == http.StatusNotFound:
		return "api_not_found"
	case status >= 300 && status < 400:
		return "api_redirect_refused"
	default:
		return "api_http_error"
	}
}

func newHandler(api apiClient, token auth.StaticToken) http.Handler {
	return protect(streamHandler(api), token)
}

// ManagementHandler builds the diagnostics transport behind management OAuth.
func ManagementHandler(transport http.RoundTripper) http.Handler {
	return streamHandler(apiClient{baseURL: "https://localhost", http: &http.Client{Transport: transport, Timeout: 8 * time.Second}})
}

func streamHandler(api apiClient) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "easy-waf", Version: easywaf.Version()}, &mcp.ServerOptions{
		SupportedProtocolVersions: []string{protocolVersion},
	})
	for _, tool := range []struct{ name, path, description string }{
		{"status", "/ready", "Check whether the Easy WAF management API and its database are ready."},
		{"doctor", "/doctor", "Check PostgreSQL, applied edge configuration and HAProxy runtime statistics in one report."},
		{"edge_status", "/edge", "Report saved and applied configuration generations and the live HAProxy artifact identity."},
		{"haproxy_check", "/haproxy", "Check HAProxy runtime statistics availability and count frontend and backend states."},
		{"list_applications", "/applications", "List publication names, public hostnames, profiles and enabled or maintenance state."},
		{"certificate_expiry", "/certificates", "List certificate validity and issuance status from Easy WAF metadata."},
		{"config_revisions", "/revisions", "List the 30 most recent configuration revisions and identify the live revision when observable."},
		{"geoip_status", "/geoip", "Report the configured GeoIP provider, enablement and cache counters."},
		{"recent_events", "/recent-events", "List the latest audited edge management attempts from the last 24 hours, with category and HTTP status."},
	} {
		mcp.AddTool(server, &mcp.Tool{
			Name: tool.name, Description: tool.description,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return api.read(ctx, tool.path, nil), nil, nil
		})
	}
	registerDescribeApplication(server, api)
	registerIPDiagnostics(server, api)
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 32 << 10,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transport.ServeHTTP(&diagnosticsResponseWriter{ResponseWriter: w}, r)
	})
}

// The SDK sets its own streaming cache directives after authentication. Apply
// the diagnostics policy when headers are sent and preserve streaming flushes.
type diagnosticsResponseWriter struct {
	http.ResponseWriter
	started bool
}

func (w *diagnosticsResponseWriter) start() {
	if !w.started {
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.started = true
	}
}

func (w *diagnosticsResponseWriter) WriteHeader(status int) {
	w.start()
	w.ResponseWriter.WriteHeader(status)
}

func (w *diagnosticsResponseWriter) Write(p []byte) (int, error) {
	w.start()
	return w.ResponseWriter.Write(p)
}

func (w *diagnosticsResponseWriter) FlushError() error {
	w.start()
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *diagnosticsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func registerIPDiagnostics(server *mcp.Server, api apiClient) {
	type arguments struct {
		IP string `json:"ip" jsonschema:"Client IPv4 or IPv6 address"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name: "why_blocked", Description: "Compare stored local IP lists, cached GeoIP and current CrowdSec bans for an address. It does not establish the outcome of a specific request.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input arguments) (*mcp.CallToolResult, any, error) {
		ip, err := netip.ParseAddr(input.IP)
		if err != nil || ip.Zone() != "" {
			return nil, nil, fmt.Errorf("one IPv4 or IPv6 address is required")
		}
		return api.read(ctx, "/why-blocked", url.Values{"ip": {ip.Unmap().String()}}), nil, nil
	})
}

func registerDescribeApplication(server *mcp.Server, api apiClient) {
	type arguments struct {
		ID string `json:"id" jsonschema:"Application ID returned by list_applications"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name: "describe_application", Description: "Check publication, DNS, TLS, applied routing and backend availability for an application ID.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input arguments) (*mcp.CallToolResult, any, error) {
		if input.ID == "" {
			return nil, nil, fmt.Errorf("application id is required")
		}
		return api.read(ctx, "/application", url.Values{"id": {input.ID}}), nil, nil
	})
}

func protect(next http.Handler, token auth.StaticToken) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.EscapedPath() != "/mcp" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !peer.Addr().Unmap().IsLoopback() || !localAuthority(r.Host) || len(r.Header.Values("Origin")) != 0 {
			http.Error(w, "local MCP clients only", http.StatusForbidden)
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) == 1 {
			scheme, value, ok := strings.Cut(values[0], " ")
			if ok && strings.EqualFold(scheme, "Bearer") && token.Matches(value) {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func localAuthority(authority string) bool {
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		host = strings.TrimPrefix(strings.TrimSuffix(authority, "]"), "[")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.Unmap().IsLoopback()
}
