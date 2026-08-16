package api

import (
	"fmt"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

var errBackendTLSVerify = fmt.Errorf("backend_tls_verify must be %q or %q",
	config.BackendTLSVerifyRequired, config.BackendTLSVerifyNone)

// validateAppHostnames checks everything that ends up inside generated HAProxy
// configuration. The same rules run again inside haproxy.Render (see
// config.ValidateApplicationRenderSafety), so a value that skips this handler
// cannot reach the config file either.
func validateAppHostnames(app *config.Application) error {
	return config.ValidateApplicationRenderSafety(app)
}

func validateBackendTLS(stateDir string, app *config.Application) error {
	if app == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(app.BackendTLSVerify))
	if v != "" && v != config.BackendTLSVerifyRequired && v != config.BackendTLSVerifyNone {
		return errBackendTLSVerify
	}
	if err := config.ValidateBackendCAFile(stateDir, app.BackendTLSCAFile); err != nil {
		return err
	}
	return config.ValidateBackendTLSServerName(app.BackendTLSServerName)
}

func validateHAProxyPath(field, path string) error {
	return config.ValidateHAProxyPath(field, path)
}
