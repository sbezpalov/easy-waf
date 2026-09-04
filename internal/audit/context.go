// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package audit

import "context"

type ctxKey int

const metaKey ctxKey = 1

// Meta carries the authenticated operator and client IP for audit rows (set per HTTP request).
type Meta struct {
	User     string
	SourceIP string
}

// WithMeta attaches audit metadata to ctx (typically from Session + attachAuditRequestMeta in the API layer).
func WithMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, metaKey, m)
}

// From returns metadata previously attached to the context.
func From(ctx context.Context) (Meta, bool) {
	v := ctx.Value(metaKey)
	if v == nil {
		return Meta{}, false
	}
	m, ok := v.(Meta)
	return m, ok
}
