// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"time"
)

type ctxKey int

const principalKey ctxKey = 1

// Principal is the authenticated operator (JWT, legacy API token, or dev).
type Principal struct {
	Username           string
	MustChangePassword bool
	Role               string // config.RoleAdmin or config.RoleViewer
	IsLegacyToken      bool   // EASY_WAF_ADMIN_TOKEN — admin role without password-change gate; still needs step-up for trust writes
	ExpiresAt          time.Time
	StepUpAt           time.Time // last password confirmation in this session; zero if none
}

// WithPrincipal attaches a principal to the request context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal set by Session middleware.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok && p != nil
}
