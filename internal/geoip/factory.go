package geoip

import (
	"fmt"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// NewProviderForSettings returns a GeoProvider for the configured backend or an error.
func NewProviderForSettings(g config.GlobalSettings) (GeoProvider, error) {
	switch strings.ToLower(strings.TrimSpace(g.GeoIPProvider)) {
	case "maxmind":
		return MaxMindProvider{}, nil
	case "ipinfo", "":
		return NewIPInfoProvider(""), nil
	default:
		return nil, fmt.Errorf("geoip: unknown provider %q", g.GeoIPProvider)
	}
}
