package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
		SELECT id, username, password_hash, must_change_password, created_at, updated_at
		FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u *config.AdminUser) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, must_change_password, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		u.ID, u.Username, u.PasswordHash, u.MustChangePassword, u.CreatedAt, u.UpdatedAt)
	return err
}

// UpdateUserPassword sets a new bcrypt hash and clears must_change_password.
func (s *Store) UpdateUserPassword(ctx context.Context, userID, passwordHash string, mustChange bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = $2, must_change_password = $3, updated_at = $4 WHERE id = $1`,
		userID, passwordHash, mustChange, time.Now().UTC())
	return err
}

// EnsureDefaultAdmin creates admin/admin if the users table is empty (first boot).
func (s *Store) EnsureDefaultAdmin(ctx context.Context) (created bool, err error) {
	n, err := s.CountUsers(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), 12)
	if err != nil {
		return false, err
	}
	err = s.CreateUser(ctx, &config.AdminUser{
		Username:           "admin",
		PasswordHash:       string(hash),
		MustChangePassword: true,
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
