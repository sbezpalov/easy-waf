package ipbl

import (
	"log"
	"net/netip"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// ParseFeedAllowedPrefixes builds dial/URL allowlist from global settings.
// Invalid CIDR strings are logged and skipped. Deprecated IPBLAllowPrivateFetch
// (when no explicit CIDRs) adds RFC1918 prefixes for backward compatibility.
func ParseFeedAllowedPrefixes(g config.GlobalSettings) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range g.IPBLFetchAllowedCIDRs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			log.Printf("[easy-waf] ipbl: skip invalid ipbl_fetch_allowed_cidrs %q: %v", s, err)
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 && g.IPBLAllowPrivateFetch {
		out = []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
		}
	}
	return out
}
