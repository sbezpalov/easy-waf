// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type MCPGrant struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ApprovedBy string     `json:"approved_by"`
	LastUsed   *time.Time `json:"last_used"`
}

func (s *Store) ApproveMCP(ctx context.Context, grant MCPGrant, issuer, client, redirect, challenge, code string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO mcp_oauth_grants(id,name,approved_by,issuer,client_id,redirect_uri,challenge,code_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, grant.ID, grant.Name, grant.ApprovedBy, issuer, client, redirect, challenge, code)
	return err
}

func (s *Store) ExchangeMCP(ctx context.Context, issuer, client, code, redirect, challenge, access, refresh string) error {
	return s.db.QueryRowContext(ctx, `UPDATE mcp_oauth_grants SET code_hash=NULL,access_hash=$6,refresh_hash=$7,access_until=now()+interval '10 minutes' WHERE issuer=$1 AND client_id=$2 AND code_hash=$3 AND redirect_uri=$4 AND challenge=$5 AND code_until>now() RETURNING 1`, issuer, client, code, redirect, challenge, access, refresh).Scan(new(int))
}

func (s *Store) RefreshMCP(ctx context.Context, issuer, client, old, access, refresh string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	err = tx.QueryRowContext(ctx, `UPDATE mcp_oauth_grants
 SET access_hash=$4, refresh_hash=$5, access_until=now()+interval '10 minutes'
 WHERE issuer=$1 AND client_id=$2 AND refresh_hash=$3 AND valid_until>now() RETURNING id`,
		issuer, client, old, access, refresh).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// Reuse of a rotated refresh token invalidates the whole grant.
		_, err = tx.ExecContext(ctx, `DELETE FROM mcp_oauth_grants g USING mcp_oauth_spent_refresh s
      WHERE s.grant_id=g.id AND g.issuer=$1 AND g.client_id=$2 AND s.token_hash=$3`, issuer, client, old)
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_spent_refresh(token_hash,grant_id) VALUES($1,$2)`, old, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UseMCP(ctx context.Context, issuer, access string) error {
	return s.db.QueryRowContext(ctx, `UPDATE mcp_oauth_grants SET last_used=now() WHERE issuer=$1 AND access_hash=$2 AND access_until>now() AND valid_until>now() RETURNING 1`, issuer, access).Scan(new(int))
}

func (s *Store) MCPGrants(ctx context.Context, issuer string) ([]MCPGrant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,approved_by,last_used FROM mcp_oauth_grants WHERE issuer=$1 AND valid_until>now() AND (access_hash IS NOT NULL OR code_until>now()) ORDER BY name,id`, issuer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []MCPGrant{}
	for rows.Next() {
		var g MCPGrant
		if err := rows.Scan(&g.ID, &g.Name, &g.ApprovedBy, &g.LastUsed); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *Store) RevokeMCP(ctx context.Context, issuer, id string) error {
	err := s.db.QueryRowContext(ctx, `DELETE FROM mcp_oauth_grants WHERE issuer=$1 AND id=$2 RETURNING 1`, issuer, id).Scan(new(int))
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}
