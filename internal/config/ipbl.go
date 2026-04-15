package config

import "time"

// IPBLLocalEntry is a user-managed CIDR or single IP for denylist (HAProxy map source).
type IPBLLocalEntry struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IPBLExternalSource is a downloadable blocklist (plain text, one IP/CIDR per line).
type IPBLExternalSource struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	Enabled        bool       `json:"enabled"`
	RefreshSeconds int        `json:"refresh_seconds"`
	LastFetchAt    *time.Time `json:"last_fetch_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}
