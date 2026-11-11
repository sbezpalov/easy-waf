// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import "time"

// AdminUser is a local operator account (management plane only).
type AdminUser struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	PasswordHash       string `json:"-"`
	MustChangePassword bool   `json:"must_change_password"`
	// Role is admin (default) or viewer (read-only panel access).
	Role string `json:"role"`
	// TOTPSecret is set when two-factor sign-in is on.
	TOTPSecret     string    `json:"-"`
	TOTPLastStep   int64     `json:"-"`
	TOTPEnabled    bool      `json:"totp_enabled"`
	SessionVersion int       `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Panel roles.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// ValidRole reports whether r is a known panel role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleViewer }
