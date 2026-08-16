package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync/atomic"
	"testing"
)

type migrationCountingDriver struct {
	execs atomic.Int64
}

func (d *migrationCountingDriver) Open(string) (driver.Conn, error) {
	return &migrationCountingConn{execs: &d.execs}, nil
}

type migrationCountingConn struct {
	execs *atomic.Int64
}

func (c *migrationCountingConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *migrationCountingConn) Close() error                        { return nil }
func (c *migrationCountingConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c *migrationCountingConn) Ping(context.Context) error          { return nil }

func (c *migrationCountingConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.execs.Add(1)
	return driver.RowsAffected(0), nil
}

func TestDiagnosticStoreOpenSkipsMigrations(t *testing.T) {
	t.Parallel()

	const driverName = "easy-waf-test-diagnostic-no-migrations"
	drv := &migrationCountingDriver{}
	sql.Register(driverName, drv)

	st, err := openPostgres(driverName, "ignored", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := drv.execs.Load(); got != 0 {
		t.Fatalf("diagnostic store open executed %d migration statements", got)
	}
}

func TestApplicationStoreOpenStillRunsMigrations(t *testing.T) {
	t.Parallel()

	const driverName = "easy-waf-test-application-runs-migrations"
	drv := &migrationCountingDriver{}
	sql.Register(driverName, drv)

	st, err := openPostgres(driverName, "ignored", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if got := drv.execs.Load(); got == 0 {
		t.Fatal("application store open did not execute migrations")
	}
}

func TestMigration018LegacyBackfillDoesNotDowngradeRequired(t *testing.T) {
	t.Parallel()

	statements := splitSQLStatements(migration018SQL)
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

	normalizedMigration := strings.ToLower(strings.Join(strings.Fields(migration018SQL), " "))
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
