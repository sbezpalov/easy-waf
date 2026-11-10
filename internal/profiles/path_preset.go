// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import "github.com/easy-waf/easy-waf/internal/config"

// HAMCPPathPolicy is the exposure preset for a Home Assistant MCP server.
//
// Paths are prefixes: /api/mcp also covers /api/mcp/assist. /auth covers the
// OAuth authorize and token endpoints. The well-known document is published
// so clients can discover those endpoints. Authorization is required on the
// MCP API itself; the SSE stream gets an inactivity timeout well above the
// edge default of 50s. Rate limits are requests per 10 seconds.
func HAMCPPathPolicy() config.PathPolicy {
	return config.PathPolicy{
		Mode: config.PathModeAllowlist,
		Allow: []string{
			"/api/mcp",
			"/mcp_server/sse",
			"/auth",
			"/.well-known/oauth-authorization-server",
		},
		Rules: []config.PathRule{
			{
				PathPrefix:         "/api/mcp",
				RequireHeader:      "Authorization",
				RequireValuePrefix: "Bearer ",
				RatePer10s:         20,
			},
			{
				PathPrefix:       "/mcp_server/sse",
				ClientTimeoutSec: 3600,
				ServerTimeoutSec: 3600,
				RatePer10s:       10,
			},
			{
				PathPrefix: "/auth",
				RatePer10s: 40,
			},
		},
	}
}

// ResolvePathPolicy keeps a stored policy when the request omits path_policy,
// and installs the ha-mcp preset when the profile is ha-mcp and nobody chose
// a policy yet. Mode "default" is a choice, so it does not receive the preset.
func ResolvePathPolicy(profile string, incoming, previous *config.PathPolicy) *config.PathPolicy {
	policy := incoming
	if policy == nil {
		policy = config.ClonePathPolicy(previous)
	}
	if profile == string(HAMCP) && (policy == nil || config.PathPolicyUnset(*policy)) {
		preset := HAMCPPathPolicy()
		return &preset
	}
	return policy
}
