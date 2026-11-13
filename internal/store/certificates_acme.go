// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/google/uuid"
)

// ErrACMEClaimLost means the certificate row changed after easy-waf-acmed claimed
// it (an operator edited it, deleted it, or another worker reclaimed it), so the
// worker's result no longer describes the row and must be discarded.
var ErrACMEClaimLost = errors.New("certificate row changed since it was claimed for ACME")

// ACMEClaimWindow selects which certificate rows easy-waf-acmed should work on.
type ACMEClaimWindow struct {
	Now time.Time
	// RenewBefore: ready ACME rows whose not_after is earlier are renewed.
	RenewBefore time.Time
	// StaleIssuing: rows left in 'issuing' longer than this (a worker crashed
	// mid-issuance) are claimed again.
	StaleIssuing time.Duration
	Limit        int
}

// ClaimCertificatesACME atomically marks due rows 'issuing' and returns them.
// A row is due when it is pending, failed with its retry time reached, ready but
// inside the renewal window, or stuck in 'issuing'. FOR UPDATE SKIP LOCKED keeps
// two workers from claiming the same row. Each returned row's UpdatedAt is the
// claim stamp the Fail/Complete calls check.
func (s *Store) ClaimCertificatesACME(ctx context.Context, w ACMEClaimWindow) ([]config.Certificate, error) {
	now := w.Now.UTC().Truncate(time.Microsecond)
	rows, err := s.db.QueryContext(ctx, `
		UPDATE certificates SET acme_status = 'issuing', updated_at = $1
		WHERE id IN (
			SELECT id FROM certificates
			WHERE acme_status = 'pending'
			   OR (acme_status = 'failed' AND (acme_next_attempt_at IS NULL OR acme_next_attempt_at <= $1))
			   OR (acme_status = 'ready' AND mode IN ('http-01', 'dns-01') AND not_after IS NOT NULL AND not_after < $2)
			   OR (acme_status = 'issuing' AND updated_at < $3)
			ORDER BY updated_at ASC
			LIMIT $4
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+certificateColumns,
		now, w.RenewBefore.UTC(), now.Add(-w.StaleIssuing), w.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificates(rows)
}

// TouchCertificateACMEClaim refreshes the claim stamp on an in-flight issuance
// so a long Obtain cannot be reclaimed as "stale" by another worker.
// Updates c.UpdatedAt to the new stamp when successful.
func (s *Store) TouchCertificateACMEClaim(ctx context.Context, c *config.Certificate) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET updated_at = $3
		WHERE id = $1 AND acme_status = 'issuing' AND updated_at = $2`,
		c.ID, c.UpdatedAt, now)
	if err != nil {
		return err
	}
	if err := claimHeld(res); err != nil {
		return err
	}
	c.UpdatedAt = now
	return nil
}

// FailCertificateACME records a failed attempt on a claimed row and schedules
// the retry at next. Returns ErrACMEClaimLost when the claim no longer holds.
func (s *Store) FailCertificateACME(ctx context.Context, c *config.Certificate, lastErr string, next time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates
		SET acme_status = 'failed', last_error = $3, acme_attempts = acme_attempts + 1,
		    acme_next_attempt_at = $4, updated_at = $5
		WHERE id = $1 AND acme_status = 'issuing' AND updated_at = $2`,
		c.ID, c.UpdatedAt, nullStrPtr(lastErr), next.UTC(), time.Now().UTC())
	if err != nil {
		return err
	}
	return claimHeld(res)
}

// ACMEResult is what a successful issuance leaves on disk.
type ACMEResult struct {
	FullchainPath, KeyPath string
	NotBefore, NotAfter    time.Time
	Mode                   string
}

// CompleteCertificateACME locks the claim and writes a complete immutable PEM
// generation before committing its paths, metadata and pending apply token in
// one transaction. A failed/ambiguous commit must never delete the generation:
// the old row still has its old paths, or the committed new row owns these files.
func (s *Store) CompleteCertificateACME(
	ctx context.Context,
	c *config.Certificate,
	write func() (ACMEResult, error),
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	var id string
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM certificates
		WHERE id = $1 AND acme_status = 'issuing' AND updated_at = $2
		FOR UPDATE`, c.ID, c.UpdatedAt).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrACMEClaimLost
	}
	if err != nil {
		return err
	}
	r, err := write()
	if err != nil {
		return fmt.Errorf("write certificate files: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE certificates
		SET acme_status = 'ready', last_error = NULL, acme_attempts = 0, acme_next_attempt_at = NULL,
		    fullchain_path = $2, pem_key_path = $3, not_before = $4, not_after = $5, mode = $6, updated_at = $7
		WHERE id = $1`,
		c.ID, r.FullchainPath, r.KeyPath, r.NotBefore.UTC(), r.NotAfter.UTC(), r.Mode, time.Now().UTC()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO acme_apply_pending (certificate_id, generation) VALUES ($1, $2)
		ON CONFLICT (certificate_id) DO UPDATE SET generation = EXCLUDED.generation`, c.ID, uuid.NewString()); err != nil {
		return err
	}
	return tx.Commit()
}

// ACMEApplyToken identifies one committed publication awaiting edge reconciliation.
// A newer publication replaces the token, so an older apply cannot clear its work.
type ACMEApplyToken struct {
	CertificateID string
	Generation    string
}

// PendingCertificateACMEApplies snapshots a bounded batch before rendering.
func (s *Store) PendingCertificateACMEApplies(ctx context.Context) ([]ACMEApplyToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT certificate_id, generation FROM acme_apply_pending ORDER BY certificate_id LIMIT 256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []ACMEApplyToken
	for rows.Next() {
		var token ACMEApplyToken
		if err := rows.Scan(&token.CertificateID, &token.Generation); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// AcknowledgeCertificateACMEApplies clears only the exact pre-apply snapshot.
// Partial acknowledgement on a query failure is safe: remaining tokens retry.
func (s *Store) AcknowledgeCertificateACMEApplies(ctx context.Context, tokens []ACMEApplyToken) error {
	for _, token := range tokens {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM acme_apply_pending WHERE certificate_id = $1 AND generation = $2`, token.CertificateID, token.Generation); err != nil {
			return err
		}
	}
	return nil
}

func claimHeld(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrACMEClaimLost
	}
	return nil
}
