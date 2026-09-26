// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadMigrationsContiguous(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range all {
		if m.version != i+1 {
			t.Fatalf("migration %s has version %d, want %d (no gaps)", m.name, m.version, i+1)
		}
	}
}

// freshSchemaDSN returns DATABASE_URL pointed at a new, empty schema that is
// dropped at cleanup, so each test migrates from scratch.
func freshSchemaDSN(t *testing.T) string {
	t.Helper()
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL not set")
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("ewmig_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func openFresh(t *testing.T, dsn string) *Store {
	t.Helper()
	st, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var schema string
	if err := st.db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(schema, "ewmig_") {
		t.Fatalf("store is on schema %q, not the fresh test schema", schema)
	}
	return st
}

func recordedMigrations(t *testing.T, st *Store) map[int]time.Time {
	t.Helper()
	rows, err := st.db.Query(`SELECT version, applied_at FROM schema_migrations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]time.Time{}
	for rows.Next() {
		var v int
		var at time.Time
		if err := rows.Scan(&v, &at); err != nil {
			t.Fatal(err)
		}
		out[v] = at
	}
	return out
}

func TestMigrateRecordsAndDoesNotReplay(t *testing.T) {
	dsn := freshSchemaDSN(t)
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	first := recordedMigrations(t, openFresh(t, dsn))
	if len(first) != len(all) {
		t.Fatalf("recorded %d migrations, want %d", len(first), len(all))
	}
	second := recordedMigrations(t, openFresh(t, dsn))
	for v, at := range first {
		if !second[v].Equal(at) {
			t.Fatalf("migration %d re-applied on second open", v)
		}
	}
}

// Deleted seed rows used to come back on every restart because migration 006
// was replayed each time.
func TestMigrateDeletedSeedStaysDeleted(t *testing.T) {
	dsn := freshSchemaDSN(t)
	st := openFresh(t, dsn)
	if err := st.DeleteBlockedUserAgent(context.Background(), "seed-nmap"); err != nil {
		t.Fatal(err)
	}
	st2 := openFresh(t, dsn)
	var n int
	if err := st2.db.QueryRow(`SELECT COUNT(*) FROM blocked_user_agents WHERE id = 'seed-nmap'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("deleted seed user agent was re-inserted on reopen")
	}
}

// api, acmed and admin start together after an upgrade; on a fresh schema
// concurrent CREATE TABLE IF NOT EXISTS can collide without the lock.
func TestMigrateConcurrentOpens(t *testing.T) {
	dsn := freshSchemaDSN(t)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := OpenPostgres(dsn)
			if err == nil {
				_ = st.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent open: %v", err)
		}
	}
}

// An appliance upgraded from a release without schema_migrations has every
// table already; the first versioned open must succeed and record everything.
func TestMigrateAdoptsPreVersioningSchema(t *testing.T) {
	dsn := freshSchemaDSN(t)
	st := openFresh(t, dsn)
	if _, err := st.db.Exec(`DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
	all, _ := loadMigrations()
	if got := recordedMigrations(t, openFresh(t, dsn)); len(got) != len(all) {
		t.Fatalf("recorded %d migrations after adopting a legacy schema, want %d", len(got), len(all))
	}
}
