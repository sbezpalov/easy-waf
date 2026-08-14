package crowdsec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultLAPIHost   = "127.0.0.1"
	defaultLAPIPort   = "8080"
	allowedOriginsEnv = "CROWDSEC_LAPI_ALLOWED_ORIGINS"
)

// Origin is a normalized LAPI destination (scheme, host, effective port).
type Origin struct {
	Scheme string
	Host   string // unbracketed, lowercase
	Port   string
}

func (o Origin) String() string {
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return o.Scheme + "://" + host + ":" + o.Port
}

func (o Origin) key() string {
	return o.Scheme + "|" + o.Host + "|" + o.Port
}

// DefaultAllowedOrigins is the safe local CrowdSec LAPI set.
func DefaultAllowedOrigins() []Origin {
	return []Origin{
		{Scheme: "http", Host: "127.0.0.1", Port: defaultLAPIPort},
		{Scheme: "http", Host: "::1", Port: defaultLAPIPort},
	}
}

// OriginsFromEnv parses CROWDSEC_LAPI_ALLOWED_ORIGINS (comma-separated URLs).
func OriginsFromEnv() ([]Origin, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(os.Getenv(allowedOriginsEnv), "\r", ""))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]Origin, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		o, err := ParseOrigin(p)
		if err != nil {
			return nil, fmt.Errorf("CROWDSEC_LAPI_ALLOWED_ORIGINS: %w", err)
		}
		out = append(out, o)
	}
	return out, nil
}

func mergeAllowlist(extra []Origin) []Origin {
	seen := map[string]struct{}{}
	var out []Origin
	add := func(o Origin) {
		k := o.key()
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, o)
	}
	for _, o := range DefaultAllowedOrigins() {
		add(o)
	}
	for _, o := range extra {
		add(o)
	}
	return out
}

// ParseOrigin normalizes an http(s) URL without userinfo to scheme/host/port.
func ParseOrigin(raw string) (Origin, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Origin{}, fmt.Errorf("empty url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, fmt.Errorf("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Origin{}, fmt.Errorf("scheme not allowed")
	}
	if u.User != nil {
		return Origin{}, fmt.Errorf("userinfo is not allowed")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return Origin{}, fmt.Errorf("missing host")
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(host)
	if host == "localhost" {
		host = "127.0.0.1"
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if strings.ContainsAny(host, " \t\r\n@") {
			return Origin{}, fmt.Errorf("invalid host")
		}
	}
	return Origin{Scheme: u.Scheme, Host: host, Port: port}, nil
}

// ValidateLAPIURL checks that raw is an allowed origin. extra comes from tests or callers;
// CROWDSEC_LAPI_ALLOWED_ORIGINS is always merged.
func ValidateLAPIURL(raw string, extra []Origin) (Origin, error) {
	o, err := ParseOrigin(raw)
	if err != nil {
		return Origin{}, err
	}
	env, err := OriginsFromEnv()
	if err != nil {
		return Origin{}, err
	}
	allow := mergeAllowlist(append(append([]Origin(nil), extra...), env...))
	for _, a := range allow {
		if a.key() == o.key() {
			return o, nil
		}
		// 127.0.0.1 and ::1 are distinct; IPv4-mapped ::ffff:127.0.0.1 → 127.0.0.1
		if sameLoopbackOrigin(a, o) {
			return o, nil
		}
	}
	return Origin{}, fmt.Errorf("lapi origin is not allowlisted")
}

func sameLoopbackOrigin(a, b Origin) bool {
	if a.Scheme != b.Scheme || a.Port != b.Port {
		return false
	}
	ia, ea := netip.ParseAddr(a.Host)
	ib, eb := netip.ParseAddr(b.Host)
	if ea != nil || eb != nil {
		return false
	}
	ia = ia.Unmap()
	ib = ib.Unmap()
	return ia.IsLoopback() && ib.IsLoopback() && ia.Is4() == ib.Is4() && ia == ib
}

func (o Origin) allowedDialIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("invalid destination ip")
	}
	ip = ip.Unmap()
	hostIP, err := netip.ParseAddr(o.Host)
	if err == nil {
		hostIP = hostIP.Unmap()
		if ip != hostIP {
			return fmt.Errorf("lapi destination IP mismatch")
		}
		return nil
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("lapi destination IP not allowed")
	}
	if ip.IsLoopback() {
		// Hostname allowlist must not rebind to loopback services.
		return fmt.Errorf("lapi destination IP not allowed")
	}
	if isMetadataIP(ip) {
		return fmt.Errorf("lapi destination IP not allowed")
	}
	return nil
}

func isMetadataIP(ip netip.Addr) bool {
	if ip.Is4() && ip.String() == "169.254.169.254" {
		return true
	}
	if !ip.Is4() {
		// AWS IMDS v2 IPv6
		want, err := netip.ParseAddr("fd00:ec2::254")
		if err == nil && ip == want {
			return true
		}
	}
	return false
}

func redactErr(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	lower := strings.ToLower(s)
	if strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "x-api-key") {
		return errors.New("crowdsec lapi request failed")
	}
	return errors.New(s)
}

func (c Client) allowlist() []Origin {
	extra := append([]Origin(nil), c.AllowedOrigins...)
	env, err := OriginsFromEnv()
	if err == nil {
		extra = append(extra, env...)
	}
	return mergeAllowlist(extra)
}

func (c Client) resolvedOrigin() (Origin, error) {
	return ValidateLAPIURL(c.BaseURL, c.AllowedOrigins)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		// Still enforce no-redirect even when a test injects a client.
		out := *c.HTTP
		out.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		if out.Timeout == 0 {
			out.Timeout = 8 * time.Second
		}
		return &out
	}
	origin, err := c.resolvedOrigin()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if err != nil {
				return nil, redactErr(err)
			}
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("lapi dial: %w", splitErr)
			}
			if port != origin.Port {
				return nil, fmt.Errorf("lapi destination port not allowed")
			}
			ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if lookupErr != nil {
				return nil, fmt.Errorf("lapi resolve: %w", lookupErr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("lapi resolve: no addresses")
			}
			var firstErr error
			for _, ia := range ips {
				addr, parseErr := netip.ParseAddr(ia.IP.String())
				if parseErr != nil {
					firstErr = parseErr
					continue
				}
				if err := origin.allowedDialIP(addr); err != nil {
					firstErr = err
					continue
				}
				tcpAddr := &net.TCPAddr{IP: ia.IP, Port: atoiPort(port), Zone: ia.Zone}
				conn, err := dialer.DialContext(ctx, network, tcpAddr.String())
				if err != nil {
					firstErr = err
					continue
				}
				return conn, nil
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("lapi destination not allowed")
			}
			return nil, firstErr
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Timeout:   8 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func atoiPort(p string) int {
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
