package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Client is a minimal CrowdSec LAPI client for health and decisions (scaffolding).
type Client struct {
	BaseURL        string
	APIKey         string
	HTTP           *http.Client
	AllowedOrigins []Origin // optional extra origins (tests / explicit policy)
}

// setLAPIAuth sets the bouncer API key header (CrowdSec LAPI uses X-Api-Key, not Bearer JWT).
func setLAPIAuth(req *http.Request, apiKey string) {
	if k := strings.TrimSpace(apiKey); k != "" {
		req.Header.Set("X-Api-Key", k)
	}
}

func (c *Client) lapiURL(pathQuery string) (string, error) {
	if _, err := c.resolvedOrigin(); err != nil {
		return "", err
	}
	base := strings.TrimSuffix(strings.TrimSpace(c.BaseURL), "/")
	if !strings.HasPrefix(pathQuery, "/") {
		pathQuery = "/" + pathQuery
	}
	return base + pathQuery, nil
}

func (c *Client) doLAPI(ctx context.Context, method, pathQuery string, body io.Reader, header http.Header) (*http.Response, error) {
	u, err := c.lapiURL(pathQuery)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, redactErr(err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	setLAPIAuth(req, c.APIKey)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, redactErr(err)
	}
	return resp, nil
}

// Status holds a lightweight integration snapshot for the UI.
type Status struct {
	Reachable   bool   `json:"reachable"`
	LastMessage string `json:"last_message,omitempty"`
}

// Ping checks whether LAPI responds (no auth required for some versions; may 401).
func (c *Client) Ping(ctx context.Context) Status {
	if strings.TrimSpace(c.BaseURL) == "" {
		return Status{Reachable: false, LastMessage: "lapi url not configured"}
	}
	resp, err := c.doLAPI(ctx, http.MethodGet, "/v1/watchers/login", nil, nil)
	if err != nil {
		return Status{Reachable: false, LastMessage: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return Status{Reachable: false, LastMessage: "lapi redirect refused"}
	}
	return Status{Reachable: true, LastMessage: fmt.Sprintf("http %d", resp.StatusCode)}
}

// DecisionsSample returns LAPI GET /v1/decisions JSON (bounded size) for UI dashboards (prompts §7.5).
func (c *Client) DecisionsSample(ctx context.Context) (json.RawMessage, error) {
	if strings.TrimSpace(c.BaseURL) == "" {
		return json.RawMessage(`[]`), nil
	}
	resp, err := c.doLAPI(ctx, http.MethodGet, "/v1/decisions?limit=100", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("crowdsec lapi decisions: redirect refused")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crowdsec lapi decisions: http %d", resp.StatusCode)
	}
	return json.RawMessage(b), nil
}

// AddDecisionRequest is the easy-waf API / UI payload mapped to LAPI POST /v1/decisions.
type AddDecisionRequest struct {
	IP       string `json:"ip"`
	Type     string `json:"type"`     // e.g. "ban" (default)
	Duration string `json:"duration"` // e.g. "24h", "168h", or "permanent"
	Reason   string `json:"reason"`   // stored as LAPI scenario
}

// lapiDecisionPost is one element of the JSON array CrowdSec LAPI expects for POST /v1/decisions.
type lapiDecisionPost struct {
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
}

// DeleteDecision calls LAPI DELETE /v1/decisions/{id}.
func (c *Client) DeleteDecision(ctx context.Context, decisionID string) error {
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return fmt.Errorf("crowdsec: empty decision id")
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("crowdsec: lapi url not configured")
	}
	resp, err := c.doLAPI(ctx, http.MethodDelete, "/v1/decisions/"+url.PathEscape(decisionID), nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return ErrDecisionNotFound
	default:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return fmt.Errorf("crowdsec lapi delete decision: redirect refused")
		}
		return fmt.Errorf("crowdsec lapi delete decision: http %d", resp.StatusCode)
	}
}

// AddDecision calls LAPI POST /v1/decisions with a single decision (ban by IP).
func (c *Client) AddDecision(ctx context.Context, req AddDecisionRequest) error {
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		return fmt.Errorf("crowdsec: empty ip")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %q", ErrInvalidDecisionIP, ip)
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("crowdsec: lapi url not configured")
	}
	decType := strings.TrimSpace(req.Type)
	if decType == "" {
		decType = "ban"
	}
	dur := mapAddDecisionDuration(strings.TrimSpace(req.Duration), decType)
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		if strings.EqualFold(decType, "whitelist") {
			reason = "manual allowlist from UI"
		} else {
			reason = "manual ban from UI"
		}
	}
	payload := []lapiDecisionPost{{
		Scope:    "Ip",
		Value:    ip,
		Type:     decType,
		Duration: dur,
		Scenario: reason,
		Origin:   "easy-waf",
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hdr := make(http.Header)
	hdr.Set("Content-Type", "application/json")
	resp, err := c.doLAPI(ctx, http.MethodPost, "/v1/decisions", bytes.NewReader(body), hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("crowdsec lapi add decision: redirect refused")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("crowdsec lapi add decision: http %d", resp.StatusCode)
	}
	return nil
}

func mapAddDecisionDuration(d, decType string) string {
	if strings.EqualFold(strings.TrimSpace(decType), "whitelist") {
		switch strings.ToLower(strings.TrimSpace(d)) {
		case "", "permanent", "876000h":
			return "876000h"
		default:
			return d
		}
	}
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", "24h":
		return "24h"
	case "1h":
		return "1h"
	case "4h":
		return "4h"
	case "7d", "168h":
		return "168h"
	case "permanent":
		// LAPI expects a duration string; use a very long window (CrowdSec/cscli style).
		return "876000h"
	default:
		// Allow raw durations like "30m" from API clients.
		return d
	}
}
