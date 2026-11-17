// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestDiagnosticStoreOpenSkipsMigrations(t *testing.T) {
	st, err := OpenPostgresForDiagnostics(freshSchemaDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var migrationsAbsent bool
	if err := st.db.QueryRowContext(t.Context(), "SELECT to_regclass('schema_migrations') IS NULL").Scan(&migrationsAbsent); err != nil {
		t.Fatal(err)
	}
	if !migrationsAbsent {
		t.Fatal("diagnostic store created the migration ledger")
	}
}

func TestInvalidConnectionSettingsReportOnlySafeDiagnostic(t *testing.T) {
	for _, dsn := range []string{
		"postgres://fixture:fixture-password%zz@localhost/easywaf",
		"host=localhost password='fixture-password",
	} {
		for _, open := range []func(string) (*Store, error){OpenPostgres, OpenPostgresForDiagnostics} {
			st, err := open(dsn)
			if st != nil {
				err = st.Ping(t.Context())
				_ = st.Close()
			}
			if !errors.Is(err, errInvalidPostgresSettings) || strings.Contains(err.Error(), "fixture-password") {
				t.Fatal("expected invalid connection settings to return a fixed diagnostic")
			}
		}
	}
}

func TestMigration018LegacyBackfillDoesNotDowngradeRequired(t *testing.T) {
	t.Parallel()

	statements := splitSQLStatements(migrationSQL("018_backend_tls_verify.sql"))
	foundLegacyBackfill := false
	for _, statement := range statements {
		normalized := strings.ToLower(strings.Join(strings.Fields(statement), " "))
		if !strings.Contains(normalized, "set backend_tls_verify = 'none'") {
			continue
		}
		foundLegacyBackfill = true
		if !strings.Contains(normalized, "backend_tls_verify is null") {
			t.Fatalf("legacy verify-none backfill must only update NULL rows: %s", normalized)
		}
		if strings.Contains(normalized, "backend_tls_verify = 'required'") {
			t.Fatalf("migration must not downgrade an operator-selected required value: %s", normalized)
		}
	}
	if !foundLegacyBackfill {
		t.Fatal("migration 018 must preserve compatibility by backfilling legacy HTTPS rows to verify none")
	}

	normalizedMigration := strings.ToLower(strings.Join(strings.Fields(migrationSQL("018_backend_tls_verify.sql")), " "))
	for _, required := range []string{
		"set backend_tls_verify = 'required' where backend_tls_verify is null",
		"alter column backend_tls_verify set default 'required'",
		"alter column backend_tls_verify set not null",
	} {
		if !strings.Contains(normalizedMigration, required) {
			t.Fatalf("migration 018 is missing repeat-safe invariant %q", required)
		}
	}
}
