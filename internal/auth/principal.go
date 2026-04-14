package auth

import "context"

type ctxKey int

const principalKey ctxKey = 1

// Principal is the authenticated operator (JWT, legacy API token, or dev).
type Principal struct {
	Username           string
	MustChangePassword bool
	IsLegacyToken      bool // EASY_WAF_ADMIN_TOKEN — full API access without password gate
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
