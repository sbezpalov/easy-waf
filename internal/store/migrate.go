// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrateAdvisoryLockKey serializes schema migration across easy-waf-api,
// easy-waf-acmed and easy-waf-admin, which all open the store on start.
const migrateAdvisoryLockKey int64 = 0x455741464d494752 // "EWAFMIGR"

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations returns the embedded migrations ordered by their numeric
// prefix (NNN_name.sql). A duplicate or malformed prefix is a build bug.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	out := make([]migration, 0, len(entries))
	seen := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: name must start with a positive number and '_'", name)
		}
		if other, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", other, name, v)
		}
		seen[v] = name
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// migrationSQL returns one embedded migration's text by file name.
func migrationSQL(name string) string {
	b, err := migrationFS.ReadFile("migrations/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// migrate applies every migration not yet recorded in schema_migrations, each
// in its own transaction, while holding a PostgreSQL advisory lock so that
// services starting together never migrate concurrently. A migration that
// fails rolls back completely and is retried on the next start.
//
// Stores created before schema_migrations existed replayed every file on each
// start, so all files are written to be repeat-safe; the first versioned start
// runs them once more and records them.
func (s *Store) migrate(ctx context.Context) (retErr error) {
	all, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("migrate: acquire lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, migrateAdvisoryLockKey); err != nil && retErr == nil {
			retErr = fmt.Errorf("migrate: release lock: %w", err)
		}
	}()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL
		)`); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}
	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	latest := 0
	for _, m := range all {
		latest = m.version
		if _, done := applied[m.version]; done {
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("migrate %s: %w", m.name, err)
		}
	}
	for v := range applied {
		if v > latest {
			// An older binary on a newer schema, e.g. after a package downgrade.
			// Newer migrations only add, so keep running, but say so.
			log.Printf("[easy-waf] store: database schema has migration %d, newer than this binary knows (%d); was the package downgraded?", v, latest)
			break
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn *sql.Conn) (map[int]struct{}, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]struct{}{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = struct{}{}
	}
	return out, rows.Err()
}

func applyMigration(ctx context.Context, conn *sql.Conn, m migration) (retErr error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range splitSQLStatements(m.sql) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
		m.version, m.name, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}
