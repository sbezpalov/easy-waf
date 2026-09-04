// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

// SecurityModeMeta is returned by GET /api/v1/security/modes for the UI.
type SecurityModeMeta struct {
	ID          string          `json:"id"`
	Label       string          `json:"label"`
	Description string          `json:"description"`
	Toggles     map[string]bool `json:"toggles"`
	ProfileHint string          `json:"profile_hint,omitempty"`
}

// SecurityModeCatalog lists presets and their default toggle snapshots.
func SecurityModeCatalog() []SecurityModeMeta {
	return []SecurityModeMeta{
		{
			ID:          string(ModeFull),
			Label:       "Full protection",
			Description: "All layers on including GeoIP; profile set to strict.",
			ProfileHint: string(Strict),
			Toggles: map[string]bool{
				"rate_limit": true, "path_acl": true, "method_filter": true, "basic_waf": true,
				"bot_protection": true, "ip_blacklist": true, "ip_allowlist": true, "geoip": true, "crowdsec": true,
			},
		},
		{
			ID:          string(ModeBalanced),
			Label:       "Balanced",
			Description: "Default home posture: all layers except GeoIP.",
			ProfileHint: string(Balanced),
			Toggles: map[string]bool{
				"rate_limit": true, "path_acl": true, "method_filter": true, "basic_waf": true,
				"bot_protection": true, "ip_blacklist": true, "ip_allowlist": true, "geoip": false, "crowdsec": true,
			},
		},
		{
			ID:          string(ModeTrustedLAN),
			Label:       "Trusted LAN",
			Description: "Minimal path ACL and no basic WAF/bot heuristics; GeoIP off.",
			ProfileHint: string(TrustedLAN),
			Toggles: map[string]bool{
				"rate_limit": true, "path_acl": false, "method_filter": true, "basic_waf": false,
				"bot_protection": false, "ip_blacklist": true, "ip_allowlist": true, "geoip": false, "crowdsec": true,
			},
		},
		{
			ID:          string(ModeReverseProxyOnly),
			Label:       "Reverse proxy only",
			Description: "Debug: routing + TLS only. Disables all WAF-style protections for this app.",
			Toggles: map[string]bool{
				"rate_limit": false, "path_acl": false, "method_filter": false, "basic_waf": false,
				"bot_protection": false, "ip_blacklist": false, "ip_allowlist": false, "geoip": false, "crowdsec": false,
			},
		},
		{
			ID:          string(ModeCustom),
			Label:       "Custom",
			Description: "Manual control of each layer.",
			Toggles:     map[string]bool{},
		},
	}
}
