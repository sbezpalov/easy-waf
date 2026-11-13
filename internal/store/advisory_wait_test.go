// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

type advisoryWaitConnector struct {
	available chan struct{}
	attempted chan struct{}
}

func (c *advisoryWaitConnector) Connect(context.Context) (driver.Conn, error) {
	return &advisoryWaitConn{owner: c}, nil
}

func (*advisoryWaitConnector) Driver() driver.Driver { return advisorySessionDriver{} }

type advisoryWaitConn struct {
	owner *advisoryWaitConnector
	held  bool
}

func (*advisoryWaitConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not used by this test")
}

func (*advisoryWaitConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not used by this test")
}

func (c *advisoryWaitConn) Close() error {
	if c.held {
		c.held = false
		c.owner.available <- struct{}{}
	}
	return nil
}

func (c *advisoryWaitConn) attempt() {
	select {
	case c.owner.attempted <- struct{}{}:
	default:
	}
}

func (c *advisoryWaitConn) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "pg_advisory_lock") {
		c.attempt()
		select {
		case <-c.owner.available:
			c.held = true
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return driver.RowsAffected(1), nil
}

func (c *advisoryWaitConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "pg_try_advisory_lock") {
		c.attempt()
		select {
		case <-c.owner.available:
			c.held = true
			return &advisorySessionRows{value: true}, nil
		default:
			return &advisorySessionRows{value: false}, nil
		}
	}
	wasHeld := c.held
	_ = c.Close()
	return &advisorySessionRows{value: wasHeld}, nil
}

func TestAdvisoryWaiterLeavesPoolCapacityForOwner(t *testing.T) {
	connector := &advisoryWaitConnector{available: make(chan struct{}, 1), attempted: make(chan struct{}, 1)}
	connector.available <- struct{}{}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	t.Cleanup(func() { _ = db.Close() })
	st := &Store{db: db}
	ownerRelease, err := st.AcquireAdvisoryLock(t.Context(), 42)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerRelease() }()
	<-connector.attempted
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	waiterResult := make(chan error, 1)
	go func() {
		release, err := st.AcquireAdvisoryLock(ctx, 42)
		if err == nil {
			err = release()
		}
		waiterResult <- err
	}()
	select {
	case <-connector.attempted:
	case <-ctx.Done():
		t.Fatal("waiter never attempted the lock")
	}
	probeCtx, probeCancel := context.WithTimeout(t.Context(), time.Second)
	defer probeCancel()
	if _, err := db.ExecContext(probeCtx, "owner work"); err != nil {
		t.Fatalf("lock waiter exhausted the pool needed by its owner: %v", err)
	}
	if err := ownerRelease(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiterResult:
		if err != nil {
			t.Fatalf("waiter could not acquire after release: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("waiter did not finish after release")
	}
}

func TestAdvisoryWaiterCancellationReturnsPoolConnection(t *testing.T) {
	connector := &advisoryWaitConnector{available: make(chan struct{}, 1), attempted: make(chan struct{}, 1)}
	// No available token models a lock owned by another PostgreSQL session.
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	st := &Store{db: db}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		release, err := st.AcquireAdvisoryLock(ctx, 42)
		if err == nil {
			_ = release()
		}
		result <- err
	}()
	select {
	case <-connector.attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not attempt its lock")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled lock wait = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled lock wait remained blocked")
	}
	if stats := db.Stats(); stats.InUse != 0 {
		t.Fatalf("canceled waiter retained a connection: %+v", stats)
	}
}
