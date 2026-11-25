// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mcpd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

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

func (c apiClient) read(ctx context.Context, path string, query url.Values) (*mcp.CallToolResult, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+diagnosticsPath+path, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid diagnostics request")
	}
	r.URL.RawQuery = query.Encode()
	r.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, fmt.Errorf("could not reach Easy WAF diagnostics over HTTPS")
	}
	defer resp.Body.Close()
	unready := path == "/ready" && resp.StatusCode == http.StatusServiceUnavailable
	if !unready && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("diagnostics API returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil || len(body) > maxAPIResponse || !json.Valid(body) {
		return nil, fmt.Errorf("invalid or oversized Easy WAF diagnostics response")
	}
	return &mcp.CallToolResult{IsError: unready, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
}

func newHandler(api apiClient, token auth.StaticToken) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "easy-waf", Version: easywaf.Version()}, &mcp.ServerOptions{
		SupportedProtocolVersions: []string{protocolVersion},
	})
	for _, tool := range []struct{ name, path, description string }{
		{"status", "/ready", "Check whether the Easy WAF management API and its database are ready."},
		{"edge_status", "/edge", "Report saved and applied configuration generations and the live HAProxy artifact identity."},
		{"list_applications", "/applications", "List publication names, public hostnames, profiles and enabled or maintenance state."},
		{"certificate_expiry", "/certificates", "List certificate validity and issuance status from Easy WAF metadata."},
		{"config_revisions", "/revisions", "List the 30 most recent configuration revisions and identify the live revision when observable."},
		{"geoip_status", "/geoip", "Report the configured GeoIP provider, enablement and cache counters."},
	} {
		mcp.AddTool(server, &mcp.Tool{
			Name: tool.name, Description: tool.description,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			result, err := api.read(ctx, tool.path, nil)
			return result, nil, err
		})
	}
	registerDescribeApplication(server, api)
	registerIPDiagnostics(server, api)
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 32 << 10,
	})
	return protect(transport, token)
}

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
		result, err := api.read(ctx, "/why-blocked", url.Values{"ip": {ip.Unmap().String()}})
		return result, nil, err
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
		result, err := api.read(ctx, "/application", url.Values{"id": {input.ID}})
		return result, nil, err
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
