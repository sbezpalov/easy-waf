// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const ipinfoBaseURL = "https://ipinfo.io"

// IPInfoProvider calls ipinfo.io JSON API (optional token via GEOIP_IPINFO_TOKEN).
// BaseURL overrides the API root (default https://ipinfo.io); used in tests.
// Outbound requests are limited to at most one per second (simple mutex + sleep).
type IPInfoProvider struct {
	BaseURL string
	HTTP    *http.Client
	// Token from env if empty at construction.
	Token string
	// MinInterval between HTTP calls (default 1s; tests may set 0).
	MinInterval time.Duration

	mu       sync.Mutex
	lastCall time.Time
}

// NewIPInfoProvider builds a provider. Token defaults to GEOIP_IPINFO_TOKEN when blank.
func NewIPInfoProvider(token string) *IPInfoProvider {
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GEOIP_IPINFO_TOKEN"))
	}
	return &IPInfoProvider{
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		Token:       token,
		MinInterval: time.Second,
	}
}

func (p *IPInfoProvider) waitRate() {
	if p.MinInterval <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if d := p.MinInterval - now.Sub(p.lastCall); d > 0 {
		time.Sleep(d)
	}
	p.lastCall = time.Now()
}

type ipinfoResponse struct {
	Country string `json:"country"`
	Error   struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"error"`
}

// Lookup returns ISO country code for ip (host address, not CIDR).
func (p *IPInfoProvider) Lookup(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", fmt.Errorf("geoip: empty ip")
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		return "", fmt.Errorf("geoip: invalid ip %q", ip)
	}

	p.waitRate()

	base := strings.TrimSuffix(strings.TrimSpace(p.BaseURL), "/")
	if base == "" {
		base = ipinfoBaseURL
	}
	u := base + "/" + url.PathEscape(ip) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if p.Token != "" {
		q := req.URL.Query()
		q.Set("token", p.Token)
		req.URL.RawQuery = q.Encode()
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("geoip ipinfo: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var jr ipinfoResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		return "", err
	}
	if jr.Error.Message != "" {
		return "", fmt.Errorf("geoip ipinfo: %s", jr.Error.Message)
	}
	cc := strings.ToUpper(strings.TrimSpace(jr.Country))
	if len(cc) != 2 {
		return "", fmt.Errorf("geoip ipinfo: bad country %q", jr.Country)
	}
	return cc, nil
}
