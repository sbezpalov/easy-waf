// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// SetTOTPPending stores a secret that becomes active only after EnableTOTP.
func (s *Store) SetTOTPPending(ctx context.Context, username, secret string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_pending_secret = $2 WHERE username = $1`, username, secret)
	return noRowsIfNone(res, err)
}

// GetTOTPPending returns the pending secret, or "".
func (s *Store) GetTOTPPending(ctx context.Context, username string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT totp_pending_secret FROM users WHERE username = $1`, username).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// EnableTOTP activates the pending secret (it must still equal secret) with
// the step already used and the recovery code hashes.
func (s *Store) EnableTOTP(ctx context.Context, username, secret string, step int64, recoveryHashes []string) error {
	h, err := json.Marshal(recoveryHashes)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET totp_secret = $2, totp_pending_secret = '', totp_last_step = $3,
			totp_recovery_hashes = $4::jsonb, updated_at = now()
		WHERE username = $1 AND totp_pending_secret = $2`, username, secret, step, string(h))
	return noRowsIfNone(res, err)
}

// DisableTOTP removes the second factor and its recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET totp_secret = '', totp_pending_secret = '', totp_last_step = 0,
			totp_recovery_hashes = '[]'::jsonb, updated_at = now()
		WHERE username = $1`, username)
	return noRowsIfNone(res, err)
}

// UseTOTPStep records step as used; false when it (or a later one) already was.
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_secret <> '' AND totp_last_step < $2`, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// UseRecoveryCode consumes a recovery code by hash and returns how many remain.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, hash string) (int, bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		UPDATE users SET totp_recovery_hashes = totp_recovery_hashes - $2::text
		WHERE id = $1 AND totp_secret <> '' AND jsonb_exists(totp_recovery_hashes, $2::text)
		RETURNING jsonb_array_length(totp_recovery_hashes)`, userID, hash).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

func noRowsIfNone(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
