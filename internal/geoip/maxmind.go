package geoip

import (
	"context"
	"fmt"
)

// MaxMindProvider is reserved for local MMDB (same GeoProvider interface).
type MaxMindProvider struct{}

// Lookup is not implemented in MVP.
func (MaxMindProvider) Lookup(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("geoip maxmind: not implemented")
}
