package api

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$`)
var validBackendHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._:-]{0,253}[a-zA-Z0-9])?$`)
var validHAProxyPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)

func validateAppHostnames(app *config.Application) error {
	if app.ID != "" {
		if err := config.ValidateResourceID("application", app.ID); err != nil {
			return err
		}
	}
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
	for field, path := range map[string]string{
		"health_path": app.HealthPath,
		"path_prefix": app.PathPrefix,
	} {
		if err := validateHAProxyPath(field, path); err != nil {
			return err
		}
	}
	for i, rp := range app.RestrictedPaths {
		if err := validateHAProxyPath(fmt.Sprintf("restricted_paths[%d].path_prefix", i), rp.PathPrefix); err != nil {
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
	return nil
}

func validateBackendTLS(stateDir string, app *config.Application) error {
	if app == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(app.BackendTLSVerify))
	if v != "" && v != config.BackendTLSVerifyRequired && v != config.BackendTLSVerifyNone {
		return fmt.Errorf("backend_tls_verify must be %q or %q", config.BackendTLSVerifyRequired, config.BackendTLSVerifyNone)
	}
	if err := config.ValidateBackendCAFile(stateDir, app.BackendTLSCAFile); err != nil {
		return err
	}
	if err := config.ValidateBackendTLSServerName(app.BackendTLSServerName); err != nil {
		return err
	}
	if app.BackendHTTPS && v == config.BackendTLSVerifyNone {
		return nil
	}
	return nil
}

func validateHAProxyPath(field, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if len(path) > 2048 || !validHAProxyPathRe.MatchString(path) {
		return fmt.Errorf("%s must be a safe absolute URL path", field)
	}
	return nil
}
