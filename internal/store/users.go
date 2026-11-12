// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/enroll"
	"github.com/google/uuid"
)

// CountUsers returns the number of rows in users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// GetUserByUsername loads a user by login name.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*config.AdminUser, error) {
	var u config.AdminUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, must_change_password, session_version, role, totp_secret, totp_last_step, created_at, updated_at
		FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.SessionVersion, &u.Role, &u.TOTPSecret, &u.TOTPLastStep, &u.CreatedAt, &u.UpdatedAt)
	u.TOTPEnabled = u.TOTPSecret != ""
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.SessionVersion < 1 {
		u.SessionVersion = 1
	}
	return &u, nil
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u *config.AdminUser) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.SessionVersion < 1 {
		u.SessionVersion = 1
	}
	if u.Role == "" {
		u.Role = config.RoleAdmin
	}
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, must_change_password, session_version, role, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		u.ID, u.Username, u.PasswordHash, u.MustChangePassword, u.SessionVersion, u.Role, u.CreatedAt, u.UpdatedAt)
	return err
}

// UpdateUserPassword sets a new bcrypt hash, clears must_change_password, and increments session_version.
func (s *Store) UpdateUserPassword(ctx context.Context, userID, passwordHash string, mustChange bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $2,
		    must_change_password = $3,
		    session_version = session_version + 1,
		    updated_at = $4
		WHERE id = $1`,
		userID, passwordHash, mustChange, time.Now().UTC())
	return err
}

// RevokeUserSessions increments session_version, invalidating every JWT already
// issued to the user. Sign-out uses it so logging out is enforced server-side
// rather than by clearing the token in the browser and hoping nobody kept a copy.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET session_version = session_version + 1,
		    updated_at = $2
		WHERE id = $1`,
		userID, time.Now().UTC())
	return err
}

// EnsureOperatorEnrollment issues a one-time enrollment secret when the users table is empty.
// It never writes the secret to application logs. Existing operators are not reset.
func (s *Store) EnsureOperatorEnrollment(ctx context.Context, stateDir string) (created bool, path string, err error) {
	n, err := s.CountUsers(ctx)
	if err != nil {
		return false, "", err
	}
	if n > 0 {
		_ = enroll.RemoveFile(stateDir)
		return false, "", nil
	}

	var hash string
	var consumed sql.NullTime
	err = s.db.QueryRowContext(ctx, `
		SELECT secret_hash, consumed_at FROM operator_enrollment WHERE id = TRUE`).Scan(&hash, &consumed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}
	pending := err == nil && !consumed.Valid && hash != ""

	if pending {
		if existing, readErr := enroll.ReadFile(stateDir); readErr == nil && enroll.SecretEqual(existing, hash) {
			return false, enroll.FilePath(stateDir), nil
		}
	}

	secret, err := enroll.GenerateSecret()
	if err != nil {
		return false, "", err
	}
	newHash := enroll.HashSecret(secret)
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO operator_enrollment (id, secret_hash, created_at, consumed_at)
		VALUES (TRUE, $1, $2, NULL)
		ON CONFLICT (id) DO UPDATE SET
			secret_hash = EXCLUDED.secret_hash,
			created_at = EXCLUDED.created_at,
			consumed_at = NULL`,
		newHash, now)
	if err != nil {
		return false, "", err
	}
	path, err = enroll.WriteFile(stateDir, secret)
	if err != nil {
		return false, "", err
	}
	return true, path, nil
}

// VerifyEnrollmentSecret checks the one-time secret without consuming it or
// creating a user. Call this before expensive password hashing so invalid
// secrets fail fast.
func (s *Store) VerifyEnrollmentSecret(ctx context.Context, secret string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrEnrollmentAlreadyCompleted
	}
	var hash string
	var consumed sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT secret_hash, consumed_at FROM operator_enrollment WHERE id = TRUE`).Scan(&hash, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentNotPending
	}
	if err != nil {
		return err
	}
	if consumed.Valid {
		return ErrEnrollmentAlreadyCompleted
	}
	if !enroll.SecretEqual(secret, hash) {
		return ErrEnrollmentSecretMismatch
	}
	return nil
}

// ConsumeEnrollmentAndCreateUser atomically consumes the one-time secret and creates the first operator.
func (s *Store) ConsumeEnrollmentAndCreateUser(ctx context.Context, secret, username, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrEnrollmentAlreadyCompleted
	}

	var hash string
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT secret_hash, consumed_at FROM operator_enrollment WHERE id = TRUE FOR UPDATE`).Scan(&hash, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentNotPending
	}
	if err != nil {
		return err
	}
	if consumed.Valid {
		return ErrEnrollmentAlreadyCompleted
	}
	if !enroll.SecretEqual(secret, hash) {
		return ErrEnrollmentSecretMismatch
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE operator_enrollment SET consumed_at = $1 WHERE id = TRUE AND consumed_at IS NULL`, now)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrEnrollmentAlreadyCompleted
	}

	u := &config.AdminUser{
		ID:                 uuid.NewString(),
		Username:           username,
		PasswordHash:       passwordHash,
		MustChangePassword: false,
		SessionVersion:     1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, must_change_password, session_version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		u.ID, u.Username, u.PasswordHash, u.MustChangePassword, u.SessionVersion, u.CreatedAt, u.UpdatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

var (
	// ErrEnrollmentAlreadyCompleted is returned when a secret is reused or users already exist.
	ErrEnrollmentAlreadyCompleted = errors.New("enrollment already completed")
	// ErrEnrollmentNotPending is returned when no enrollment row is waiting.
	ErrEnrollmentNotPending = errors.New("enrollment is not pending")
	// ErrEnrollmentSecretMismatch is returned when the presented secret does not match.
	ErrEnrollmentSecretMismatch = errors.New("invalid enrollment secret")
)

// EnrollmentPending reports whether the first operator still needs to enroll.
func (s *Store) EnrollmentPending(ctx context.Context) (bool, error) {
	n, err := s.CountUsers(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	var consumed sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT consumed_at FROM operator_enrollment WHERE id = TRUE`).Scan(&consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !consumed.Valid, nil
}

// DeleteUserByUsername removes a local operator (tests and emergency maintenance).
func (s *Store) DeleteUserByUsername(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username = $1`, username)
	return err
}

// ErrLastAdmin refuses a change that would leave no admin.
var ErrLastAdmin = errors.New("the last admin cannot be removed or demoted")

// ListUsers returns all panel users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]config.AdminUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, must_change_password, role, totp_secret <> '', created_at, updated_at
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.AdminUser
	for rows.Next() {
		var u config.AdminUser
		if err := rows.Scan(&u.ID, &u.Username, &u.MustChangePassword, &u.Role, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserRole changes a user's role. Demoting the last admin returns
// ErrLastAdmin; an unknown user returns sql.ErrNoRows.
func (s *Store) SetUserRole(ctx context.Context, username, role string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET role = $2, updated_at = $3
		WHERE username = $1
		  AND ($2 = 'admin' OR role <> 'admin'
		       OR (SELECT count(*) FROM users WHERE role = 'admin' AND username <> $1) > 0)`,
		username, role, time.Now().UTC())
	if err != nil {
		return err
	}
	return s.lastAdminOrMissing(ctx, res, username)
}

// DeleteUser removes a panel user unless it is the last admin.
func (s *Store) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM users
		WHERE username = $1
		  AND (role <> 'admin' OR (SELECT count(*) FROM users WHERE role = 'admin' AND username <> $1) > 0)`,
		username)
	if err != nil {
		return err
	}
	return s.lastAdminOrMissing(ctx, res, username)
}

func (s *Store) lastAdminOrMissing(ctx context.Context, res sql.Result, username string) error {
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if u == nil {
		return sql.ErrNoRows
	}
	return ErrLastAdmin
}
