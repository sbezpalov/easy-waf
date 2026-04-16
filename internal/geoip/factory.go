package geoip

import (
	"fmt"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// NewProviderForSettings returns a GeoProvider for the configured backend or an error.
// For MaxMind, callers that reuse lookups should prefer ProviderForRuntime when a Runtime is available.
func NewProviderForSettings(g config.GlobalSettings) (GeoProvider, error) {
	switch strings.ToLower(strings.TrimSpace(g.GeoIPProvider)) {
	case "maxmind":
		path := strings.TrimSpace(g.GeoIPMMDBPath)
		if path == "" {
			return nil, fmt.Errorf("geoip_mmdb_path not configured")
		}
		return NewMaxMindProvider(path)
	case "ipinfo", "":
		return NewIPInfoProvider(""), nil
	default:
		return nil, fmt.Errorf("geoip: unknown provider %q", g.GeoIPProvider)
	}
}
