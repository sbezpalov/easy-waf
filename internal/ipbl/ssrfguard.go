package ipbl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// privateOrSpecial reports whether ip must never be reached by feed fetches.
func privateOrSpecial(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		isCGNAT(ip)
}

func isCGNAT(ip netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return ip.Is4() && cgnat.Contains(ip)
}

// ValidateFeedURL parses, enforces http(s), and rejects URLs whose host resolves to
// any private/special address. Use ValidateFeedURLContext when a request context is available.
func ValidateFeedURL(rawURL string, allowPrivate bool) (*url.URL, error) {
	return validateFeedURLContext(context.Background(), rawURL, allowPrivate)
}

// ValidateFeedURLContext is like ValidateFeedURL but respects ctx for DNS lookups.
func ValidateFeedURLContext(ctx context.Context, rawURL string, allowPrivate bool) (*url.URL, error) {
	return validateFeedURLContext(ctx, rawURL, allowPrivate)
}

func validateFeedURLContext(ctx context.Context, rawURL string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme not allowed: %q (use http/https)", u.Scheme)
	}
	if allowPrivate {
		return u, nil
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if privateOrSpecial(ip) {
			return nil, fmt.Errorf("url host resolves to blocked address: %s", ip)
		}
		return u, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for host %q", host)
	}
	for _, ip := range ips {
		if privateOrSpecial(ip) {
			return nil, fmt.Errorf("url host %q resolves to blocked address: %s", host, ip)
		}
	}
	return u, nil
}

// safeDialControl re-checks the actual connected IP at dial time (anti DNS rebinding).
func safeDialControl(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("dial: cannot parse ip %q", host)
		}
		if privateOrSpecial(ip) {
			return fmt.Errorf("dial blocked: %s is private/special", ip)
		}
		return nil
	}
}

// newFeedClient builds an http.Client with SSRF protections for external IPBL feeds.
func newFeedClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: safeDialControl(allowPrivate)}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:   45 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if _, err := validateFeedURLContext(req.Context(), req.URL.String(), allowPrivate); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}
