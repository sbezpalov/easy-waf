package api

import (
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	trueClientIPHdr  = http.CanonicalHeaderKey("True-Client-IP")
	xForwardedForHdr = http.CanonicalHeaderKey("X-Forwarded-For")
	xRealIPHdr       = http.CanonicalHeaderKey("X-Real-IP")
)

// defaultTrustedProxyCIDRs are TCP peers allowed to set client IP via forwarding headers.
// Direct clients (e.g. WAN → 0.0.0.0:8000) are not in this list, so X-Forwarded-For cannot bypass management ACL.
func defaultTrustedProxyCIDRs() []string {
	return []string{"127.0.0.0/8", "::1/128"}
}

// TrustedProxyCIDRs returns CIDRs for reverse proxies that may set X-Forwarded-For / X-Real-IP / True-Client-IP.
// Override with EASY_WAF_TRUSTED_PROXY_CIDRS (comma-separated) when the management proxy is not on loopback
// (e.g. NGINX on 192.168.1.5 → easy-waf-api:8000).
func TrustedProxyCIDRs() []string {
	raw := strings.TrimSpace(os.Getenv("EASY_WAF_TRUSTED_PROXY_CIDRS"))
	if raw == "" {
		return defaultTrustedProxyCIDRs()
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultTrustedProxyCIDRs()
	}
	return out
}

// clientIPFromForwardingHeaders mirrors chi middleware.RealIP header precedence.
func clientIPFromForwardingHeaders(r *http.Request) string {
	var ip string
	if tcip := r.Header.Get(trueClientIPHdr); tcip != "" {
		ip = strings.TrimSpace(tcip)
	} else if xrip := r.Header.Get(xRealIPHdr); xrip != "" {
		ip = strings.TrimSpace(xrip)
	} else if xff := r.Header.Get(xForwardedForHdr); xff != "" {
		xff = strings.TrimSpace(xff)
		if i := strings.Index(xff, ","); i >= 0 {
			ip = strings.TrimSpace(xff[:i])
		} else {
			ip = xff
		}
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// TrustedRealIP rewrites Request.RemoteAddr from forwarding headers only when the TCP peer
// (connection source) is in trustedProxyCIDRs. Otherwise RemoteAddr stays the direct peer,
// preventing management ACL bypass via spoofed X-Forwarded-For.
func TrustedRealIP(trustedProxyCIDRs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, peerOK := clientIP(r)
			if peerOK && ipAllowed(peer, trustedProxyCIDRs) {
				if rip := clientIPFromForwardingHeaders(r); rip != "" {
					r.RemoteAddr = rip
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
