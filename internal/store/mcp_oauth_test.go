// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestMCPGrantLifetime(t *testing.T) {
	dsn := freshSchemaDSN(t)
	s := openFresh(t, dsn)
	ctx := t.Context()
	g := MCPGrant{ID: "bc2c9298-8e83-43e2-9e52-0211626773d8", Name: "agent", ApprovedBy: "operator"}
	requireOK := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	requireInactive := func(err error) {
		t.Helper()
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("expected inactive credential, got %v", err)
		}
	}
	status := func(want string) {
		t.Helper()
		rows, err := s.MCPGrants(ctx)
		requireOK(err)
		if len(rows) != 1 || rows[0].Status != want {
			t.Fatalf("expected one grant in state %s, got %+v", want, rows)
		}
	}
	approve := func() { requireOK(s.ApproveMCP(ctx, g, "issuer", "client", "redirect", "challenge", "code")) }
	exchange := func() error {
		return s.ExchangeMCP(ctx, "issuer", "client", "code", "redirect", "challenge", "access", "refresh")
	}
	past := time.Now().Add(-time.Hour)
	approve()
	status("pending")
	requireOK(s.SetMCPGrantExpiry(ctx, g.ID, &past))
	requireInactive(exchange())
	status("expired")
	requireInactive(s.SetMCPGrantExpiry(ctx, g.ID, nil))
	requireOK(s.RevokeMCP(ctx, g.ID))
	approve()
	_, err := s.db.ExecContext(ctx, "UPDATE mcp_oauth_grants SET code_until=$1 WHERE id=$2", past, g.ID)
	requireOK(err)
	status("setup_expired")
	requireInactive(exchange())
	requireOK(s.RevokeMCP(ctx, g.ID))
	approve()
	requireOK(exchange())
	requireOK(s.Close())
	s = openFresh(t, dsn)
	status("connected")
	requireOK(s.UseMCP(ctx, "issuer", "access"))
	requireOK(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a2", "r2"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a3", "r3"))
	status("reauth_required")
	requireInactive(s.UseMCP(ctx, "issuer", "a2"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "r2", "a3", "r3"))
	requireInactive(s.SetMCPGrantExpiry(ctx, g.ID, nil))
	requireOK(s.RevokeMCP(ctx, g.ID))
	approve()
	requireOK(exchange())
	requireOK(s.SetMCPGrantExpiry(ctx, g.ID, &past))
	requireInactive(s.UseMCP(ctx, "issuer", "access"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a2", "r2"))
	status("expired")
}
