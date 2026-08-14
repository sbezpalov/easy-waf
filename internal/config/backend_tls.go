package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	BackendTLSVerifyRequired = "required"
	BackendTLSVerifyNone     = "none"
	DefaultSystemCABundle    = "/etc/ssl/certs/ca-certificates.crt"
)

// NormalizeBackendTLS sets canonical verify mode. Empty becomes required.
func NormalizeBackendTLS(a *Application) {
	if a == nil {
		return
	}
	v := strings.ToLower(strings.TrimSpace(a.BackendTLSVerify))
	switch v {
	case "", BackendTLSVerifyRequired:
		a.BackendTLSVerify = BackendTLSVerifyRequired
	case BackendTLSVerifyNone:
		a.BackendTLSVerify = BackendTLSVerifyNone
	default:
		a.BackendTLSVerify = BackendTLSVerifyRequired
	}
	a.BackendTLSCAFile = strings.TrimSpace(a.BackendTLSCAFile)
	a.BackendTLSServerName = strings.TrimSpace(a.BackendTLSServerName)
}

// BackendTLSInsecure reports an explicit verify-none HTTPS backend.
func BackendTLSInsecure(a Application) bool {
	return a.BackendHTTPS && strings.EqualFold(strings.TrimSpace(a.BackendTLSVerify), BackendTLSVerifyNone)
}

// ValidateBackendCAFile allows the Ubuntu system bundle or a file under an allowlisted directory.
func ValidateBackendCAFile(stateDir, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("backend_tls_ca_file must be an absolute path")
	}
	if strings.IndexFunc(path, unicode.IsSpace) >= 0 || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("backend_tls_ca_file contains unsupported characters")
	}
	clean := filepath.Clean(path)
	if clean == DefaultSystemCABundle {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(clean))
	if ext != ".crt" && ext != ".pem" {
		return fmt.Errorf("backend_tls_ca_file must be a .crt or .pem file")
	}
	allowed := []string{
		"/etc/easy-waf/ca/",
		filepath.Clean(filepath.Join(stateDir, "ca")) + string(filepath.Separator),
	}
	for _, prefix := range allowed {
		if strings.HasPrefix(clean, prefix) {
			rel, err := filepath.Rel(filepath.Dir(strings.TrimSuffix(prefix, string(filepath.Separator))), clean)
			if err != nil || strings.HasPrefix(rel, "..") {
				return fmt.Errorf("backend_tls_ca_file is outside the allowlisted CA directory")
			}
			return nil
		}
	}
	return fmt.Errorf("backend_tls_ca_file is not an allowlisted CA path")
}

// ValidateBackendTLSServerName allows a DNS name or IP for SNI/verifyhost.
func ValidateBackendTLSServerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if strings.ContainsAny(name, " \t\r\n#;") {
		return fmt.Errorf("backend_tls_server_name contains unsupported characters")
	}
	if len(name) > 253 {
		return fmt.Errorf("backend_tls_server_name is too long")
	}
	return nil
}
