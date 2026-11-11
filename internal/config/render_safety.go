// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Value safety for everything that reaches the generated HAProxy configuration.
//
// These checks run at the API boundary (on write) *and* again in
// haproxy.Render (on every apply). The duplication is deliberate: the renderer
// interpolates these fields straight into config lines, so a single missed
// validator — a second write path, a restored backup, a hand-edited row — would
// turn a stored value into arbitrary HAProxy directives. A newline in
// public_host is enough to append `http-request allow` to a security block, and
// `haproxy -c` would happily accept the result.
var (
	// Lowercase, and no '_'. Both restrictions carry weight beyond tidiness:
	// HAProxy matches the Host header case-insensitively (`hdr(host) -i`), so
	// two rows differing only in case are two ACLs that both fire on the same
	// request — one application's allow rule then short-circuits another's
	// denies. And '_' collides with the '.'→'_' identifier mapping in
	// haproxy.sanitizeHAProxyIdent, which is what makes that mapping injective.
	// Neither character is legal in a DNS hostname anyway, and a public host
	// has to be a real name to get a certificate.
	validHostnameRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$`)
	validBackendHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._:-]{0,253}[a-zA-Z0-9])?$`)
	validHAProxyPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
	// Filesystem paths that end up inside a directive or a crt-list entry. The
	// class deliberately excludes whitespace, '#', quotes, '\' and '$': each of
	// those either ends the directive, comments out what follows, or is expanded
	// by HAProxy's own parser. Absoluteness is not checked here — that is a
	// deployment question the API enforces on write, not a rendering hazard.
	validConfigFilePathRe = regexp.MustCompile(`^[A-Za-z0-9._~+@:/-]+$`)
	// Proxy, engine and ACL identifiers.
	validHAProxyIdentRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// ValidateConfigFilePath rejects a filesystem path that could break out of the
// configuration line it is rendered into.
//
// A newline is the obvious one, but a space is just as good: `ca-file /a b`
// silently makes `b` the next token of the server line, and `#` comments out the
// rest of it. Whether the path also has to be absolute is decided by the caller
// — api.validateRuntimeSettings requires it, the renderer does not.
func ValidateConfigFilePath(field, path string, allowEmpty bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(path) > 4096 {
		return fmt.Errorf("%s is too long", field)
	}
	if !validConfigFilePathRe.MatchString(path) {
		return fmt.Errorf("%s must be an absolute path without spaces or shell metacharacters", field)
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return fmt.Errorf("%s must not contain '..'", field)
		}
	}
	return nil
}

// ValidateHAProxyIdent checks a name rendered as a proxy, engine or ACL
// identifier.
func ValidateHAProxyIdent(field, value string) error {
	if !validHAProxyIdentRe.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%s contains unsupported characters", field)
	}
	return nil
}

// ValidateSettingsRenderSafety checks every global setting that is interpolated
// into HAProxy configuration.
//
// Same reasoning as ValidateApplicationRenderSafety, and the same gap it exists
// to close: these were checked only in the settings handler, so a value that
// reached the row by any other route — a restored backup, a direct UPDATE, a
// future second write path — was rendered verbatim. A newline in
// crowdsec_engine_name is enough to plant a bare `http-request allow` in the
// frontend, which short-circuits every deny after it.
func ValidateSettingsRenderSafety(s *GlobalSettings) error {
	if s == nil {
		return nil
	}
	if strings.TrimSpace(s.CrowdSecEngineName) != "" {
		if err := ValidateHAProxyIdent("crowdsec_engine_name", s.CrowdSecEngineName); err != nil {
			return err
		}
	}
	if err := ValidateListenAddr("acme_internal_http", s.ACMEInternalHTTP); err != nil {
		return err
	}
	if err := validateSourceList("trusted_proxy_cidrs", s.TrustedProxyCIDRs); err != nil {
		return err
	}
	if err := validateSourceList("proxy_protocol_cidrs", s.ProxyProtocolCIDRs); err != nil {
		return err
	}
	if h := s.RealIPHeader; h != "" && !slices.Contains(RealIPHeaders, h) {
		return fmt.Errorf("real_ip_header must be one of %s", strings.Join(RealIPHeaders, ", "))
	}
	// Emptiness is a functional question the renderer already handles (an unset
	// map path simply omits the directive), so this only asks that whatever *is*
	// set is safe to interpolate. Requiring values here would turn a partially
	// configured appliance into a failed apply for no security gain.
	paths := map[string]string{
		"haproxy_config_path":          s.HAProxyConfigPath,
		"haproxy_stats_socket_path":    s.HAProxyStatsSocketPath,
		"haproxy_binary":               s.HAProxyBinary,
		"geoip_enforce_map_path":       s.GeoIPEnforceMapPath,
		"ip_blacklist_map_path":        s.IPBlacklistMapPath,
		"ip_allowlist_map_path":        s.IPAllowlistMapPath,
		"blocked_user_agents_map_path": s.BlockedUserAgentsMapPath,
		"spoe_config_path":             s.SPOEConfigPath,
		"geoip_mmdb_path":              s.GeoIPMMDBPath,
	}
	for name, path := range paths {
		if err := ValidateConfigFilePath(name, path, true); err != nil {
			return err
		}
	}
	return nil
}

// validateSourceList accepts IP addresses and CIDR prefixes, which are rendered
// inline into `src` ACLs.
func validateSourceList(field string, list []string) error {
	for i, raw := range list {
		raw = strings.TrimSpace(raw)
		if _, err := netip.ParseAddr(raw); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("%s[%d] is not an IP or CIDR", field, i)
		}
	}
	return nil
}

// DefaultACMEInternalHTTP is the loopback address the HTTP-01 helper listens on
// and the generated bk_acme backend points at.
const DefaultACMEInternalHTTP = "127.0.0.1:8089"

// ACMEInternalHTTPOrDefault resolves the configured HTTP-01 helper address,
// falling back to the default for a partially configured appliance. Callers that
// render must go through this, so that an unset setting and the shipped default
// produce the same config line.
func ACMEInternalHTTPOrDefault(v string) string {
	if strings.TrimSpace(v) == "" {
		return DefaultACMEInternalHTTP
	}
	return strings.TrimSpace(v)
}

// ValidateListenAddr accepts an empty value (meaning "use the default") or an
// ip:port literal.
//
// A hostname is refused on purpose. The value is interpolated into a `server`
// line, and a name there would need a `resolvers` section that the renderer only
// emits when an application backend asks for one — so a hostname would render a
// config that HAProxy rejects at start, after the validation step has passed.
// Requiring a literal also means no character that could open a second directive
// can survive parsing.
func ValidateListenAddr(name, value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%s must be ip:port (e.g. %s)", name, DefaultACMEInternalHTTP)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("%s must use an IP literal, not a hostname (e.g. %s)", name, DefaultACMEInternalHTTP)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%s port must be 1-65535", name)
	}
	return nil
}

// ValidateCertificateRenderSafety checks the paths of a certificate that reach
// the crt-list.
//
// A crt-list holds one entry per line, so a newline in a stored path becomes a
// second entry — and an entry may carry an SNI filter, which means a `*` on that
// line takes over certificate selection for every vhost. Nothing validated these
// fields before: the API handler checked only the certificate ID.
func ValidateCertificateRenderSafety(c *Certificate) error {
	if c == nil {
		return nil
	}
	if c.ID != "" {
		if err := ValidateResourceID("certificate", c.ID); err != nil {
			return err
		}
	}
	for field, path := range map[string]string{
		"pem_crt_path":   c.PEMCrtPath,
		"pem_key_path":   c.PEMKeyPath,
		"bundle_path":    c.BundlePath,
		"fullchain_path": c.FullchainPath,
	} {
		if err := ValidateConfigFilePath(field, path, true); err != nil {
			return err
		}
	}
	return nil
}

// ValidateHAProxyPath rejects a path that could break out of the directive it is
// rendered into.
func ValidateHAProxyPath(field, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if len(path) > 2048 || !validHAProxyPathRe.MatchString(path) {
		return fmt.Errorf("%s must be a safe absolute URL path", field)
	}
	return nil
}

const (
	// MaxBodyBytesLimit caps max_body_bytes_override at 1 TiB.
	MaxBodyBytesLimit int64 = 1 << 40
	// MaxMultipartAllowedPaths caps multipart_allowed_paths.
	MaxMultipartAllowedPaths = 32
)

func validateBodyPolicy(sec ApplicationSecurity) error {
	if m := sec.MaxBodyBytesOverride; m != nil && (*m < 0 || *m > MaxBodyBytesLimit) {
		return fmt.Errorf("max_body_bytes_override must be between 0 and %d", MaxBodyBytesLimit)
	}
	if len(sec.MultipartAllowedPaths) > MaxMultipartAllowedPaths {
		return fmt.Errorf("multipart_allowed_paths allows at most %d entries", MaxMultipartAllowedPaths)
	}
	for i, p := range sec.MultipartAllowedPaths {
		field := fmt.Sprintf("multipart_allowed_paths[%d]", i)
		lower := strings.ToLower(p)
		if strings.Trim(p, "/") == "" || strings.Contains(lower, "..") || strings.Contains(lower, "%2e") {
			return fmt.Errorf("%s must be a specific path prefix", field)
		}
		// HAProxy expands $NAME from its environment in unquoted config text.
		if strings.ContainsAny(p, "$'") {
			return fmt.Errorf("%s must not contain $ or '", field)
		}
		if err := ValidateHAProxyPath(field, p); err != nil {
			return err
		}
	}
	return nil
}

// ValidateApplicationRenderSafety checks every application field that is
// interpolated into HAProxy configuration.
func ValidateApplicationRenderSafety(app *Application) error {
	if app == nil {
		return nil
	}
	if app.ID != "" {
		if err := ValidateResourceID("application", app.ID); err != nil {
			return err
		}
	}
	// Name is rendered into a config comment: a newline would end the comment.
	if len(app.Name) > 200 || strings.ContainsAny(app.Name, "\x00\r\n") {
		return fmt.Errorf("name contains invalid control characters or is too long")
	}
	if !validHostnameRe.MatchString(app.PublicHost) {
		if strings.ToLower(app.PublicHost) != app.PublicHost {
			return fmt.Errorf("public_host must be lowercase: HAProxy matches the Host header case-insensitively, so %q and its lowercase form would both match the same request", app.PublicHost)
		}
		return fmt.Errorf("public_host contains invalid characters (allowed: a-z, 0-9, ., -)")
	}
	if !validBackendHostRe.MatchString(app.BackendHost) {
		return fmt.Errorf("backend_host contains invalid characters")
	}
	if app.BackendPort < 1 || app.BackendPort > 65535 {
		return fmt.Errorf("backend_port must be 1-65535")
	}
	if strings.ContainsAny(app.PublicHost, "\n\r\t;#") {
		return fmt.Errorf("public_host contains control characters")
	}
	if strings.ContainsAny(app.BackendHost, "\n\r\t;#") {
		return fmt.Errorf("backend_host contains control characters")
	}
	if err := validateBackendServers(app); err != nil {
		return err
	}
	if len(app.MaintenanceBypassCIDRs) > 64 {
		return fmt.Errorf("maintenance_bypass_cidrs: at most 64 entries")
	}
	if err := validateSourceList("maintenance_bypass_cidrs", app.MaintenanceBypassCIDRs); err != nil {
		return err
	}
	if err := ValidateHAProxyPath("health_path", app.HealthPath); err != nil {
		return err
	}
	if err := ValidateHAProxyPath("path_prefix", app.PathPrefix); err != nil {
		return err
	}
	if err := validateBodyPolicy(app.Security); err != nil {
		return err
	}
	if err := ValidatePathPolicy(app.PathPolicy); err != nil {
		return err
	}
	for i, rp := range app.RestrictedPaths {
		if err := ValidateHAProxyPath(fmt.Sprintf("restricted_paths[%d].path_prefix", i), rp.PathPrefix); err != nil {
			return err
		}
		for j, raw := range rp.AllowedCIDRs {
			raw = strings.TrimSpace(raw)
			if _, err := netip.ParseAddr(raw); err == nil {
				continue
			}
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("restricted_paths[%d].allowed_cidrs[%d] is not an IP or CIDR", i, j)
			}
		}
	}
	// backend_tls_ca_file is interpolated straight into the `server` line
	// (haproxy.backendTLSOptions). It was validated only in the API handler,
	// which is exactly the arrangement this function exists to distrust.
	if err := ValidateConfigFilePath("backend_tls_ca_file", app.BackendTLSCAFile, true); err != nil {
		return err
	}
	return ValidateBackendTLSServerName(app.BackendTLSServerName)
}

func validateBackendServers(app *Application) error {
	if !slices.Contains(BackendBalances, app.BackendBalance) {
		return fmt.Errorf("backend_balance must be roundrobin, leastconn or source")
	}
	if len(app.BackendServers) > MaxBackendServers {
		return fmt.Errorf("backend_servers: at most %d entries", MaxBackendServers)
	}
	seen := map[string]bool{strings.ToLower(app.BackendHost) + ":" + strconv.Itoa(app.BackendPort): true}
	for i, sv := range app.BackendServers {
		if !validBackendHostRe.MatchString(sv.Host) {
			return fmt.Errorf("backend_servers[%d].host contains invalid characters", i)
		}
		if sv.Port < 1 || sv.Port > 65535 {
			return fmt.Errorf("backend_servers[%d].port must be 1-65535", i)
		}
		key := strings.ToLower(sv.Host) + ":" + strconv.Itoa(sv.Port)
		if seen[key] {
			return fmt.Errorf("backend_servers[%d]: %s is listed twice", i, key)
		}
		seen[key] = true
	}
	return nil
}
