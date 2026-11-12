// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"os"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
)

// hostHasIPv6 reports whether the kernel has IPv6 enabled. HAProxy cannot bind
// an IPv6 socket otherwise, and `haproxy -c` does not bind, so only the reload
// would fail.
var hostHasIPv6 = func() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

func validateRuntimeSettings(s config.GlobalSettings) error {
	// The identifier and path rules live in config.ValidateSettingsRenderSafety
	// so that the handler and the renderer cannot drift apart; this function adds
	// the checks that only make sense at the API boundary.
	if err := config.ValidateSettingsRenderSafety(&s); err != nil {
		return err
	}
	// On write the paths must also be absolute: a relative one resolves against
	// whatever directory the service happened to start in.
	required := map[string]string{
		"haproxy_config_path":          s.HAProxyConfigPath,
		"haproxy_stats_socket_path":    s.HAProxyStatsSocketPath,
		"haproxy_binary":               s.HAProxyBinary,
		"geoip_enforce_map_path":       s.GeoIPEnforceMapPath,
		"ip_blacklist_map_path":        s.IPBlacklistMapPath,
		"ip_allowlist_map_path":        s.IPAllowlistMapPath,
		"blocked_user_agents_map_path": s.BlockedUserAgentsMapPath,
	}
	for name, path := range required {
		if err := config.ValidateAbsoluteConfigFilePath(name, path, false); err != nil {
			return err
		}
	}
	if err := config.ValidateAbsoluteConfigFilePath("spoe_config_path", s.SPOEConfigPath, true); err != nil {
		return err
	}
	if s.ListenIPv6 && !hostHasIPv6() {
		return fmt.Errorf("listen_ipv6: IPv6 is disabled on this host (/proc/net/if_inet6 is missing)")
	}
	if raw := strings.TrimSpace(s.CrowdSecLAPIURL); raw != "" {
		if _, err := crowdsec.ValidateLAPIURL(raw, nil); err != nil {
			return fmt.Errorf("crowdsec_lapi_url: %w", err)
		}
	}
	return nil
}
