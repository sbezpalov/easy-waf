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

// AppEnforceMapPath is the HAProxy src map path for one application's GeoIP policy.
func AppEnforceMapPath(stateDir, appID string) string {
	id := strings.Map(func(r rune) rune {
		switch r {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_':
			return r
		default:
			return '_'
		}
	}, appID)
	if strings.TrimSpace(id) == "" {
		id = "app"
	}
	return filepath.Join(stateDir, "haproxy", "geoip_app_"+id+".map")
}

// WriteEnforceMap resolves each blacklist CIDR to a country (first address of the network),
// uses cache+provider, and writes HAProxy src map lines (one CIDR per line) for CIDRs that
// match the current allow/deny country policy. Empty list → empty map file (ACL disabled).
func WriteEnforceMap(ctx context.Context, prov GeoProvider, cache *MemoryCache, g config.GlobalSettings, stateDir string, blacklistCIDRs []string) error {
	out := EnforceMapPath(g, stateDir)
	_ = os.MkdirAll(filepath.Dir(out), 0o750)
	return writeEnforceMapCore(ctx, prov, cache, g.GeoIPDefaultPolicy, g.GeoIPCountryList, blacklistCIDRs, out)
}

// WriteAppEnforceMap writes a per-application GeoIP map using app-level policy and country list.
func WriteAppEnforceMap(ctx context.Context, prov GeoProvider, cache *MemoryCache, policy string, countries []string, blacklistCIDRs []string, outPath string) error {
	_ = os.MkdirAll(filepath.Dir(outPath), 0o750)
	return writeEnforceMapCore(ctx, prov, cache, policy, countries, blacklistCIDRs, outPath)
}

func writeEnforceMapCore(ctx context.Context, prov GeoProvider, cache *MemoryCache, defaultPolicy string, countryList []string, blacklistCIDRs []string, out string) error {
	list := normalizeCountryList(countryList)
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
		policy := strings.ToLower(strings.TrimSpace(defaultPolicy))
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

// WriteDisabledAppEnforceMap clears a per-application GeoIP map file.
func WriteDisabledAppEnforceMap(path string) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	return writeMapFile(path, "# easy-waf geoip enforce — app scope disabled\n")
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

// HasCountryTargets reports whether the list contains at least one valid alpha-2 code.
func HasCountryTargets(countries []string) bool {
	return len(normalizeCountryList(countries)) > 0
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
