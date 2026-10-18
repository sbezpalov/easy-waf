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
	// BeforeID, when > 0, returns only rows with id < BeforeID: keyset
	// paging, which stays as cheap on the last page as on the first, unlike
	// Offset (the server reads and discards every skipped row).
	BeforeID int64
	User     string // ILIKE match on user_name
	Action   string // ILIKE match on action
	From     *time.Time
	To       *time.Time // exclusive upper bound when set
}

// auditWhere builds the WHERE clause from the filters actually set. A single
// statement with an "unset or matches" clause per filter looked simpler, but once
// the driver's cached prepared statement switches PostgreSQL to a generic plan
// the planner cannot drop the unused branches: on 2M rows the unfiltered first
// page then took 7 ms instead of 0.3 ms, and the count 140 ms instead of 67 ms.
func auditWhere(p AuditListParams) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, arg any) {
		args = append(args, arg)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if v := strings.TrimSpace(p.User); v != "" {
		add(`COALESCE(user_name,'') ILIKE '%%' || $%d || '%%' ESCAPE '\'`, escapeLike(v))
	}
	if v := strings.TrimSpace(p.Action); v != "" {
		add(`action ILIKE '%%' || $%d || '%%' ESCAPE '\'`, escapeLike(v))
	}
	if p.From != nil {
		add("at >= $%d", *p.From)
	}
	if p.To != nil {
		add("at < $%d", *p.To)
	}
	if p.BeforeID > 0 {
		add("id < $%d", p.BeforeID)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListAuditLogs returns up to p.Limit rows ordered by id descending, and
// whether more rows match beyond them (found by reading one extra row, so
// paging needs no COUNT).
func (s *Store) ListAuditLogs(ctx context.Context, p AuditListParams) ([]config.AuditLogEntry, bool, error) {
	if p.Limit <= 0 {
		p.Limit = 100
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	where, args := auditWhere(p)
	args = append(args, p.Limit+1, p.Offset)
	// where and the LIMIT/OFFSET placeholders are fixed text built above;
	// every value is a bound parameter.
	//nolint:gosec // G202: no user input in the SQL text
	q := `
		SELECT id, at, COALESCE(user_name,''), action, COALESCE(source_ip,''), detail_json
		FROM audit_log` + where + fmt.Sprintf(`
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []config.AuditLogEntry
	for rows.Next() {
		var e config.AuditLogEntry
		var raw []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserName, &e.Action, &e.SourceIP, &raw); err != nil {
			return nil, false, err
		}
		if len(raw) > 0 && string(raw) != "null" {
			e.Details = json.RawMessage(raw)
		} else {
			e.Details = json.RawMessage("null")
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > p.Limit
	if hasMore {
		out = out[:p.Limit]
	}
	return out, hasMore, nil
}

// CountAuditLogs returns how many rows match the same filters as ListAuditLogs
// (BeforeID included). It reads every matching row — 70-600 ms on 2M rows —
// so the API runs it only on request.
func (s *Store) CountAuditLogs(ctx context.Context, p AuditListParams) (int64, error) {
	where, args := auditWhere(p)
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`+where, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// likeEscaper makes a filter match literally: % and _ in a user or action
// filter were LIKE wildcards, so "a_b" also matched "aXb".
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLike(s string) string { return likeEscaper.Replace(s) }
