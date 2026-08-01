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

// hardBlocked IPs/ranges that cannot be overridden by ipbl_fetch_allowed_cidrs (loopback, metadata, etc.).
func hardBlocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return ip.IsLoopback() ||
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

// softBlocked is RFC1918-style private space; may be allowed via ipbl_fetch_allowed_cidrs.
func softBlocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return ip.IsPrivate()
}

func checkDestIP(ip netip.Addr, allowed []netip.Prefix) error {
	if hardBlocked(ip) {
		return fmt.Errorf("blocked (hard): %s", ip)
	}
	if softBlocked(ip) {
		for _, p := range allowed {
			if p.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("private address %s not in ipbl_fetch_allowed_cidrs", ip)
	}
	return nil
}

// ValidateFeedURLContext parses URL and checks resolved/dial destinations against allowlist.
func ValidateFeedURLContext(ctx context.Context, rawURL string, allowed []netip.Prefix) (*url.URL, error) {
	return validateFeedURLContext(ctx, rawURL, allowed)
}

func validateFeedURLContext(ctx context.Context, rawURL string, allowed []netip.Prefix) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme not allowed: %q (use http/https)", u.Scheme)
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := checkDestIP(ip, allowed); err != nil {
			return nil, fmt.Errorf("url host: %w", err)
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
		if err := checkDestIP(ip, allowed); err != nil {
			return nil, fmt.Errorf("url host %q: %w", host, err)
		}
	}
	return u, nil
}

func safeDialControl(allowed []netip.Prefix) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("dial: cannot parse ip %q", host)
		}
		if err := checkDestIP(ip, allowed); err != nil {
			return fmt.Errorf("dial blocked: %w", err)
		}
		return nil
	}
}

// newFeedClient builds an http.Client with SSRF protections for external IPBL feeds.
func newFeedClient(allowed []netip.Prefix) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: safeDialControl(allowed)}
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
			if _, err := validateFeedURLContext(req.Context(), req.URL.String(), allowed); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}
