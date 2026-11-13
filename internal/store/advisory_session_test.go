// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

var errAdvisorySessionTest = errors.New("advisory lock reply lost")

// Use a Connector so every test owns its driver state without global registration.
type advisorySessionConnector struct {
	mu       sync.Mutex
	failure  string
	opened   int
	closed   int
	unlocked int
}

func (c *advisorySessionConnector) Connect(context.Context) (driver.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opened++
	return &advisorySessionConn{owner: c}, nil
}

func (c *advisorySessionConnector) Driver() driver.Driver { return advisorySessionDriver{} }

type advisorySessionDriver struct{}

func (advisorySessionDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use the test connector")
}

type advisorySessionConn struct {
	owner *advisorySessionConnector
	held  bool
}

func (c *advisorySessionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not used by this test")
}

func (c *advisorySessionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not used by this test")
}

func (c *advisorySessionConn) Close() error {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	c.owner.closed++
	c.held = false
	return nil
}

func (c *advisorySessionConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "pg_advisory_lock") {
		c.held = true
		if c.owner.failure == "acquire" {
			// Model a server-side lock whose success was lost in transit.
			return nil, errAdvisorySessionTest
		}
	} else if c.held {
		return nil, errors.New("pooled connection still owns an advisory lock")
	}
	return driver.RowsAffected(1), nil
}

func (c *advisorySessionConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.owner.mu.Lock()
	c.owner.unlocked++
	c.owner.mu.Unlock()
	switch c.owner.failure {
	case "unlock":
		return nil, errAdvisorySessionTest
	case "not-held":
		c.held = false
		return &advisorySessionRows{value: false}, nil
	default:
		c.held = false
		return &advisorySessionRows{value: true}, nil
	}
}

type advisorySessionRows struct {
	value bool
	done  bool
}

func (*advisorySessionRows) Columns() []string { return []string{"unlocked"} }
func (*advisorySessionRows) Close() error      { return nil }
func (r *advisorySessionRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

func TestAdvisoryLockDiscardsUncertainSession(t *testing.T) {
	for _, failure := range []string{"acquire", "unlock", "not-held"} {
		t.Run(failure, func(t *testing.T) {
			connector := &advisorySessionConnector{failure: failure}
			db := sql.OpenDB(connector)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			t.Cleanup(func() { _ = db.Close() })
			st := &Store{db: db}
			release, err := st.AcquireAdvisoryLock(t.Context(), 42)
			if failure != "acquire" {
				if err != nil {
					t.Fatal(err)
				}
				err = release()
				if again := release(); again != err {
					t.Fatalf("repeat release changed its result: %v -> %v", err, again)
				}
			}
			if err == nil || failure != "not-held" && !errors.Is(err, errAdvisorySessionTest) {
				t.Fatalf("lost lock failure: %v", err)
			}
			if _, err := db.ExecContext(t.Context(), "probe"); err != nil {
				t.Fatalf("uncertain lock session returned to pool: %v", err)
			}
			if connector.opened != 2 || connector.closed != 1 {
				t.Fatalf("uncertain connection was not discarded exactly once: opened=%d closed=%d", connector.opened, connector.closed)
			}
			if failure != "acquire" && connector.unlocked != 1 {
				t.Fatalf("repeat release retried unlock: calls=%d", connector.unlocked)
			}
		})
	}
}

func TestAdvisoryLockReusesSuccessfullyUnlockedSession(t *testing.T) {
	connector := &advisorySessionConnector{}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	st := &Store{db: db}
	release, err := st.AcquireAdvisoryLock(t.Context(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "probe"); err != nil {
		t.Fatal(err)
	}
	if connector.opened != 1 || connector.closed != 0 || connector.unlocked != 1 {
		t.Fatalf("healthy session was discarded or unlocked twice: opened=%d closed=%d unlocked=%d", connector.opened, connector.closed, connector.unlocked)
	}
}
