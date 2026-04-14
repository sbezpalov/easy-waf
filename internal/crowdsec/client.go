package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal CrowdSec LAPI client for health and decisions (scaffolding).
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// Status holds a lightweight integration snapshot for the UI.
type Status struct {
	Reachable   bool   `json:"reachable"`
	LastMessage string `json:"last_message,omitempty"`
}

// Ping checks whether LAPI responds (no auth required for some versions; may 401).
func (c *Client) Ping(ctx context.Context) Status {
	if c.BaseURL == "" {
		return Status{Reachable: false, LastMessage: "lapi url not configured"}
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/watchers/login", nil)
	if err != nil {
		return Status{Reachable: false, LastMessage: err.Error()}
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Status{Reachable: false, LastMessage: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	// Any HTTP response means TCP/TLS reached something
	return Status{Reachable: true, LastMessage: fmt.Sprintf("http %d", resp.StatusCode)}
}

// DecisionsSample returns LAPI GET /v1/decisions JSON (bounded size) for UI dashboards (prompts §7.5).
func (c *Client) DecisionsSample(ctx context.Context) (json.RawMessage, error) {
	if strings.TrimSpace(c.BaseURL) == "" {
		return json.RawMessage(`[]`), nil
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	base := strings.TrimSuffix(strings.TrimSpace(c.BaseURL), "/")
	u := base + "/v1/decisions?limit=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crowdsec lapi decisions: http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.RawMessage(b), nil
}
