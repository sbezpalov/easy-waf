package config

import "time"

// BlockedUserAgent is a substring matched case-insensitively against the User-Agent header.
type BlockedUserAgent struct {
	ID        string    `json:"id"`
	Pattern   string    `json:"pattern"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
