// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"fmt"
	"time"
)

// ProfileName is a preset security posture.
type ProfileName string

const (
	Balanced      ProfileName = "balanced"
	Strict        ProfileName = "strict"
	TrustedLAN    ProfileName = "trusted-lan"
	PublicApp     ProfileName = "public-app"
	HomeAssistant ProfileName = "home-assistant"
	None          ProfileName = "none"
	Custom        ProfileName = "custom"
)

// Profile defines tunables for HAProxy templates and ACLs.
type Profile struct {
	Name                ProfileName
	Description         string
	RateLimitRPS        int
	RateLimitBurst      int
	ConnectTimeout      time.Duration
	ServerTimeout       time.Duration
	HTTPKeepAlive       bool
	BlockPaths          []string
	ExtraBlockedMethods []string // e.g. TRACE
	GeoDefaultDeny      bool
	Notes               string
}

// All returns built-in profiles for UI and validation.
func All() map[ProfileName]Profile {
	return map[ProfileName]Profile{
		Balanced: {
			Name:                Balanced,
			Description:         "Reasonable defaults for most home apps",
			RateLimitRPS:        50,
			RateLimitBurst:      100,
			ConnectTimeout:      5 * time.Second,
			ServerTimeout:       50 * time.Second,
			HTTPKeepAlive:       true,
			BlockPaths:          defaultBlockedPaths(),
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
		},
		Strict: {
			Name:                Strict,
			Description:         "Tighter limits and broader path blocks",
			RateLimitRPS:        20,
			RateLimitBurst:      40,
			ConnectTimeout:      3 * time.Second,
			ServerTimeout:       30 * time.Second,
			HTTPKeepAlive:       true,
			BlockPaths:          append(defaultBlockedPaths(), "/.svn", "/.hg", "/cgi-bin"),
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
			GeoDefaultDeny:      false,
		},
		TrustedLAN: {
			Name:           TrustedLAN,
			Description:    "High trust; minimal friction on LAN-heavy setups",
			RateLimitRPS:   200,
			RateLimitBurst: 400,
			ConnectTimeout: 5 * time.Second,
			ServerTimeout:  120 * time.Second,
			HTTPKeepAlive:  true,
			BlockPaths:     minimalBlockedPaths(),
		},
		PublicApp: {
			Name:                PublicApp,
			Description:         "Internet-exposed generic HTTP app",
			RateLimitRPS:        30,
			RateLimitBurst:      60,
			ConnectTimeout:      5 * time.Second,
			ServerTimeout:       60 * time.Second,
			BlockPaths:          defaultBlockedPaths(),
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
		},
		HomeAssistant: {
			Name:                HomeAssistant,
			Description:         "WebSocket-friendly timeouts and HA-specific path allowances",
			RateLimitRPS:        40,
			RateLimitBurst:      80,
			ConnectTimeout:      5 * time.Second,
			ServerTimeout:       3600 * time.Second,
			HTTPKeepAlive:       true,
			BlockPaths:          defaultBlockedPaths(),
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
			Notes:               "Long server timeout for SSE/WebSocket; still block obvious probes",
		},
		None: {
			Name:                None,
			Description:         "No profile path blocks; high rate limits — combine with per-app security toggles",
			RateLimitRPS:        500,
			RateLimitBurst:      1000,
			ConnectTimeout:      5 * time.Second,
			ServerTimeout:       300 * time.Second,
			HTTPKeepAlive:       true,
			BlockPaths:          nil,
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
		},
		Custom: {
			Name:                Custom,
			Description:         "Alias of balanced numeric defaults; tuning is via per-app toggles and overrides",
			RateLimitRPS:        50,
			RateLimitBurst:      100,
			ConnectTimeout:      5 * time.Second,
			ServerTimeout:       50 * time.Second,
			HTTPKeepAlive:       true,
			BlockPaths:          defaultBlockedPaths(),
			ExtraBlockedMethods: []string{"TRACE", "CONNECT"},
		},
	}
}

func defaultBlockedPaths() []string {
	return []string{
		"/.git", "/.env", "/.svn", "/.hg",
		"/wp-admin", "/wp-login.php", "/xmlrpc.php",
		"/.well-known/security.txt", // keep acme challenge separate via ACL order
		"/vendor/phpunit",
		"/config", "/backup.sql",
	}
}

func minimalBlockedPaths() []string {
	return []string{"/.git", "/.env"}
}

// Resolve returns profile or error if unknown.
func Resolve(name string) (Profile, error) {
	pn := ProfileName(name)
	p, ok := All()[pn]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q", name)
	}
	return p, nil
}
