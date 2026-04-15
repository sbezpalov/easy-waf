package audit

import (
	"net"
	"net/http"
	"strings"
)

// ClientHost returns the client IP string (chi RealIP may have normalized RemoteAddr).
func ClientHost(r *http.Request) string {
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
