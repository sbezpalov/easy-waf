package api

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
)

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
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
		if !filepath.IsAbs(strings.TrimSpace(path)) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if raw := strings.TrimSpace(s.SPOEConfigPath); raw != "" && !filepath.IsAbs(raw) {
		return fmt.Errorf("spoe_config_path must be an absolute path")
	}
	if raw := strings.TrimSpace(s.CrowdSecLAPIURL); raw != "" {
		if _, err := crowdsec.ValidateLAPIURL(raw, nil); err != nil {
			return fmt.Errorf("crowdsec_lapi_url: %w", err)
		}
	}
	return nil
}
