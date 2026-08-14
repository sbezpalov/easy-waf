package api

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
)

var haproxyIdentifierRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func validateRuntimeSettings(s config.GlobalSettings) error {
	if !haproxyIdentifierRE.MatchString(s.CrowdSecEngineName) {
		return fmt.Errorf("crowdsec_engine_name contains unsupported characters")
	}
	paths := map[string]string{
		"haproxy_config_path":          s.HAProxyConfigPath,
		"haproxy_stats_socket_path":    s.HAProxyStatsSocketPath,
		"haproxy_binary":               s.HAProxyBinary,
		"geoip_enforce_map_path":       s.GeoIPEnforceMapPath,
		"ip_blacklist_map_path":        s.IPBlacklistMapPath,
		"ip_allowlist_map_path":        s.IPAllowlistMapPath,
		"blocked_user_agents_map_path": s.BlockedUserAgentsMapPath,
	}
	for name, path := range paths {
		if err := validateAbsoluteConfigPath(name, path, false); err != nil {
			return err
		}
	}
	if err := validateAbsoluteConfigPath("spoe_config_path", s.SPOEConfigPath, true); err != nil {
		return err
	}
	if raw := strings.TrimSpace(s.CrowdSecLAPIURL); raw != "" {
		if _, err := crowdsec.ValidateLAPIURL(raw, nil); err != nil {
			return fmt.Errorf("crowdsec_lapi_url: %w", err)
		}
	}
	return nil
}

func validateAbsoluteConfigPath(name, value string, allowEmpty bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s must not be empty", name)
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s contains unsupported whitespace", name)
	}
	return nil
}
