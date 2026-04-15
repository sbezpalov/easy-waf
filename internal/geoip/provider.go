package geoip

import "context"

// GeoProvider resolves a single host IP to an ISO 3166-1 alpha-2 country code (uppercase).
type GeoProvider interface {
	Lookup(ctx context.Context, ip string) (countryCode string, err error)
}
