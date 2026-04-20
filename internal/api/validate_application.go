package api

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$`)
var validBackendHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._:-]{0,253}[a-zA-Z0-9])?$`)

func validateAppHostnames(app *config.Application) error {
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
	return nil
}
