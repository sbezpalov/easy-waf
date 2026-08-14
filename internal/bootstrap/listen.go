package bootstrap

import (
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	httpOffSentinel      = "off"
	allowInsecureHTTPEnv = "EASY_WAF_ALLOW_INSECURE_HTTP"
)

// HTTPListenDecision is the resolved management HTTP listener (not ACME).
type HTTPListenDecision struct {
	Addr      string // empty means disabled
	Loopback  bool
	Insecure  bool // non-loopback cleartext
	Warning   string
	Refused   bool // explicit non-loopback without allow flag
	RefusedOf string
}

func envTrim(key string) string {
	return strings.TrimSpace(strings.ReplaceAll(os.Getenv(key), "\r", ""))
}

func truthyEnv(key string) bool {
	v := strings.ToLower(envTrim(key))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func isDisabledListen(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "" || s == "off" || s == "disabled" || s == "none" || s == "false" || s == "0"
}

func splitHostPort(addr string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("empty listen address")
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func hostIsLoopback(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResolveManagementHTTP decides whether the full management API is served on cleartext HTTP.
// Default (unset): disabled. Loopback is allowed. Non-loopback requires EASY_WAF_ALLOW_INSECURE_HTTP=1.
func ResolveManagementHTTP(flagHTTP, flagLegacy string) HTTPListenDecision {
	raw := strings.TrimSpace(flagHTTP)
	if raw == "" {
		raw = envTrim("EASY_WAF_LISTEN_HTTP")
	}
	if raw == "" {
		raw = envTrim("EASY_WAF_LISTEN")
	}
	if raw == "" {
		raw = strings.TrimSpace(flagLegacy)
	}
	if isDisabledListen(raw) {
		return HTTPListenDecision{}
	}
	host, _, err := splitHostPort(raw)
	if err != nil {
		return HTTPListenDecision{
			Refused:   true,
			RefusedOf: raw,
			Warning:   fmt.Sprintf("invalid EASY_WAF_LISTEN_HTTP %q: %v", raw, err),
		}
	}
	if hostIsLoopback(host) {
		return HTTPListenDecision{Addr: raw, Loopback: true}
	}
	if !truthyEnv(allowInsecureHTTPEnv) {
		return HTTPListenDecision{
			Refused:   true,
			RefusedOf: raw,
			Warning:   fmt.Sprintf("refusing non-loopback management HTTP %s; set %s=1 to enable legacy cleartext (discouraged) or use HTTPS", raw, allowInsecureHTTPEnv),
		}
	}
	return HTTPListenDecision{
		Addr:     raw,
		Insecure: true,
		Warning:  fmt.Sprintf("WARNING: management API is serving cleartext HTTP on %s; prefer HTTPS :8443 and unset this after migrating clients", raw),
	}
}

// ResolveManagementHTTPS returns the TLS listen address. Empty/off disables HTTPS.
func ResolveManagementHTTPS(flagHTTPS string, httpsDisabled bool) string {
	if httpsDisabled {
		return ""
	}
	raw := strings.TrimSpace(flagHTTPS)
	if raw == "" {
		raw = envTrim("EASY_WAF_LISTEN_HTTPS")
	}
	if isDisabledListen(raw) && raw != "" {
		return ""
	}
	if raw == "" {
		return "0.0.0.0:8443"
	}
	return raw
}
