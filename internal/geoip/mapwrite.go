package geoip

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/ipbl"
)

// EnforceMapPath returns the path for the HAProxy src map listing CIDRs to deny for GeoIP batch MVP.
func EnforceMapPath(g config.GlobalSettings, stateDir string) string {
	if g.GeoIPEnforceMapPath != "" {
		return g.GeoIPEnforceMapPath
	}
	return filepath.Join(stateDir, "haproxy", "geoip_enforce.map")
}

// WriteEnforceMap resolves each blacklist CIDR to a country (first address of the network),
// uses cache+provider, and writes HAProxy src map lines (one CIDR per line) for CIDRs that
// match the current allow/deny country policy. Empty list → empty map file (ACL disabled).
func WriteEnforceMap(ctx context.Context, prov GeoProvider, cache *MemoryCache, g config.GlobalSettings, stateDir string, blacklistCIDRs []string) error {
	out := EnforceMapPath(g, stateDir)
	_ = os.MkdirAll(filepath.Dir(out), 0o750)

	list := normalizeCountryList(g.GeoIPCountryList)
	if len(list) == 0 {
		// No policy targets → write header-only so HAProxy ACL stays off.
		return writeMapFile(out, "# easy-waf geoip enforce — empty country list\n")
	}
	set := map[string]struct{}{}
	for _, c := range list {
		set[c] = struct{}{}
	}

	var lines []string
	for _, cidr := range blacklistCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		host, err := firstHostIP(cidr)
		if err != nil {
			continue
		}
		key := host.String()
		cc, ok := cache.Get(key)
		if !ok {
			if prov == nil {
				continue
			}
			var err error
			cc, err = prov.Lookup(ctx, key)
			if err != nil {
				continue
			}
			cache.Set(key, cc)
		}
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) != 2 {
			continue
		}
		_, inList := set[cc]
		policy := strings.ToLower(strings.TrimSpace(g.GeoIPDefaultPolicy))
		if policy == "deny" {
			// Deny-listed countries → put CIDR in enforce map.
			if !inList {
				continue
			}
		} else {
			// Allow-listed countries → deny CIDRs whose country is NOT in the list.
			if inList {
				continue
			}
		}
		lines = append(lines, cidr)
	}
	sort.Strings(lines)
	var b strings.Builder
	b.WriteString("# easy-waf geoip enforce — generated; CIDRs matching country policy (batch from IP blacklist)\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return writeMapFile(out, b.String())
}

// WriteDisabledEnforceMap writes a header-only map when GeoIP batch is off (clears stale CIDR lines).
func WriteDisabledEnforceMap(g config.GlobalSettings, stateDir string) error {
	out := EnforceMapPath(g, stateDir)
	_ = os.MkdirAll(filepath.Dir(out), 0o750)
	return writeMapFile(out, "# easy-waf geoip enforce — disabled\n")
}

func writeMapFile(path, body string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizeCountryList(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) == 2 {
			out = append(out, c)
		}
	}
	return out
}

func firstHostIP(cidr string) (net.IP, error) {
	if strings.Contains(cidr, "/") {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		_ = ip
		return n.IP, nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip")
	}
	return ip, nil
}

// UseEnforceMapInRender is true when GeoIP ACL should reference the map (enabled + non-empty entries).
func UseEnforceMapInRender(enabled bool, mapPath string) bool {
	if !enabled || mapPath == "" {
		return false
	}
	b, err := os.ReadFile(mapPath)
	if err != nil {
		return false
	}
	return ipbl.FileHasEntries(b)
}
