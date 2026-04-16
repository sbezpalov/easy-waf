package config

import "strings"

// NormalizeListenMode sets Application.ListenMode to a canonical value.
// Default: https_only (TLS on :443; HTTP redirects to HTTPS for this host).
func NormalizeListenMode(a *Application) {
	if a == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(a.ListenMode)) {
	case "http_only":
		a.ListenMode = "http_only"
	case "http_and_https":
		a.ListenMode = "http_and_https"
	case "redirect_to_https":
		a.ListenMode = "redirect_to_https"
	default:
		a.ListenMode = "https_only"
	}
}

// ListenModeRequiresCertificate reports whether the app must have certificate_id for API validation.
func ListenModeRequiresCertificate(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "http_only":
		return false
	default:
		return true
	}
}
