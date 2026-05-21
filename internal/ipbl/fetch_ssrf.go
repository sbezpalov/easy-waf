package ipbl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPrivateFetchBlocked is returned when an IPBL URL resolves to a non-public address.
var ErrPrivateFetchBlocked = fmt.Errorf("ipbl fetch: private or link-local address not allowed")

func newIPBLHTTPClient(allowPrivate bool) *http.Client {
	c := &http.Client{Timeout: 45 * time.Second}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("ipbl fetch: too many redirects")
		}
		return validateIPBLFetchURL(req.Context(), req.URL, allowPrivate)
	}
	return c
}

func validateIPBLFetchURL(ctx context.Context, u *url.URL, allowPrivate bool) error {
	if u == nil {
		return fmt.Errorf("ipbl fetch: empty url")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("ipbl fetch: scheme %q not allowed", u.Scheme)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return fmt.Errorf("ipbl fetch: empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && isBlockedFetchIP(ip) {
			return ErrPrivateFetchBlocked
		}
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("ipbl fetch: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("ipbl fetch: no addresses for %s", host)
	}
	for _, a := range addrs {
		if !allowPrivate && isBlockedFetchIP(a.IP) {
			return ErrPrivateFetchBlocked
		}
	}
	return nil
}

func isBlockedFetchIP(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127 ||
			ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 169 && ip4[1] == 254)
	}
	// IPv6: ::1, ULA fc00::/7, link-local fe80::/10
	if ip.Equal(net.IPv6loopback) {
		return true
	}
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	return false
}
