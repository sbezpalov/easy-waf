// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// AuditListParams filters and pages audit_log rows (newest first).
type AuditListParams struct {
	Limit  int
	Offset int
	User   string // ILIKE match on user_name
	Action string // ILIKE match on action
	From   *time.Time
	To     *time.Time // exclusive upper bound when set
}

// ListAuditLogs returns audit rows ordered by id descending.
func (s *Store) ListAuditLogs(ctx context.Context, p AuditListParams) ([]config.AuditLogEntry, error) {
	if p.Limit <= 0 {
		p.Limit = 100
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	userPat := strings.TrimSpace(p.User)
	actionPat := strings.TrimSpace(p.Action)
	var fromArg, toArg any
	if p.From != nil {
		fromArg = *p.From
	}
	if p.To != nil {
		toArg = *p.To
	}
	q := `
		SELECT id, at, COALESCE(user_name,''), action, COALESCE(source_ip,''), detail_json
		FROM audit_log
		WHERE ($1::text = '' OR COALESCE(user_name,'') ILIKE '%' || $1 || '%')
		  AND ($2::text = '' OR action ILIKE '%' || $2 || '%')
		  AND ($3::timestamptz IS NULL OR at >= $3::timestamptz)
		  AND ($4::timestamptz IS NULL OR at < $4::timestamptz)
		ORDER BY id DESC
		LIMIT $5 OFFSET $6`
	rows, err := s.db.QueryContext(ctx, q, userPat, actionPat, fromArg, toArg, p.Limit, p.Offset)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []config.AuditLogEntry
	for rows.Next() {
		var e config.AuditLogEntry
		var raw []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserName, &e.Action, &e.SourceIP, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 && string(raw) != "null" {
			e.Details = json.RawMessage(raw)
		} else {
			e.Details = json.RawMessage("null")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAuditLogs returns how many rows match the same filters as ListAuditLogs (for pagination hints).
func (s *Store) CountAuditLogs(ctx context.Context, p AuditListParams) (int64, error) {
	userPat := strings.TrimSpace(p.User)
	actionPat := strings.TrimSpace(p.Action)
	var fromArg, toArg any
	if p.From != nil {
		fromArg = *p.From
	}
	if p.To != nil {
		toArg = *p.To
	}
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_log
		WHERE ($1::text = '' OR COALESCE(user_name,'') ILIKE '%' || $1 || '%')
		  AND ($2::text = '' OR action ILIKE '%' || $2 || '%')
		  AND ($3::timestamptz IS NULL OR at >= $3::timestamptz)
		  AND ($4::timestamptz IS NULL OR at < $4::timestamptz)`,
		userPat, actionPat, fromArg, toArg).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}
