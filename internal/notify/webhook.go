// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Notice is one certificate an operator should look at. It carries no secret.
type Notice struct {
	Domain    string `json:"domain"`
	Attention string `json:"attention"`
	LastError string `json:"last_error,omitempty"`
}

type payload struct {
	Source       string   `json:"source"`
	Event        string   `json:"event"`
	Certificates []Notice `json:"certificates"`
}

// Notices lists certificates that need attention. An empty slice means nothing to send.
func Notices(certs []config.Certificate, now time.Time) []Notice {
	var out []Notice
	for i := range certs {
		why := config.CertificateAttention(&certs[i], now)
		if why == "" {
			continue
		}
		out = append(out, Notice{
			Domain:    certs[i].PrimaryDomain,
			Attention: why,
			LastError: strings.TrimSpace(certs[i].LastError),
		})
	}
	return out
}

// PostWebhook delivers certificate notices. Errors never include the URL: it
// may carry a token. Redirects are not followed. Link-local addresses,
// including cloud metadata, are refused. Loopback and private addresses are
// allowed so a webhook on the appliance or the LAN works.
func PostWebhook(ctx context.Context, rawURL string, notices []Notice) error {
	if len(notices) == 0 {
		return config.ValidateNotifyWebhookURL(rawURL)
	}
	body, err := json.Marshal(payload{
		Source:       "easy-waf",
		Event:        "certificate_attention",
		Certificates: notices,
	})
	if err != nil {
		return err
	}
	return postJSON(ctx, rawURL, body, "easy-waf-acmed")
}

// newClient refuses redirects and link-local destinations (see dialWebhook).
func newClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("webhook redirects are not followed")
		},
		Transport: &http.Transport{DialContext: dialWebhook},
	}
}

func postJSON(ctx context.Context, rawURL string, body []byte, userAgent string) error {
	if err := config.ValidateNotifyWebhookURL(rawURL); err != nil {
		return err
	}
	if strings.TrimSpace(rawURL) == "" {
		return errors.New("webhook url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(rawURL), bytes.NewReader(body))
	if err != nil {
		return errors.New("webhook url is not usable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := newClient().Do(req)
	if err != nil {
		if errors.Is(err, errWebhookBlocked) {
			return errWebhookBlocked
		}
		// The client wraps the redirect refusal with the request URL.
		if strings.Contains(err.Error(), "webhook redirects are not followed") {
			return errors.New("webhook redirects are not followed")
		}
		return errors.New("webhook request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

var errWebhookBlocked = errors.New("webhook destination is not allowed")

func dialWebhook(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errWebhookBlocked
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errWebhookBlocked
	}
	for _, ip := range ips {
		if webhookIPBlocked(ip) {
			return nil, errWebhookBlocked
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func webhookIPBlocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
