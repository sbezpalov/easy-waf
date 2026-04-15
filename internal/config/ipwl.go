package config

import "time"

// IPWLLocalEntry is a user-managed CIDR or single IP for the HAProxy allowlist map.
type IPWLLocalEntry struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
