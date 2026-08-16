package config

import (
	"fmt"
	"net/netip"
	"regexp"
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
	validHostnameRe    = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$`)
	validBackendHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._:-]{0,253}[a-zA-Z0-9])?$`)
	validHAProxyPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
)

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
	if err := ValidateHAProxyPath("health_path", app.HealthPath); err != nil {
		return err
	}
	if err := ValidateHAProxyPath("path_prefix", app.PathPrefix); err != nil {
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
	return ValidateBackendTLSServerName(app.BackendTLSServerName)
}
