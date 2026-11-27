// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestMigrateMCPKeepsExistingPairing(t *testing.T) {
	dsn := freshSchemaDSN(t)
	ctx := t.Context()
	legacy, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	if _, err := legacy.ExecContext(ctx, migrationSQL("030_mcp_oauth.sql")); err != nil {
		t.Fatal(err)
	}
	const id = "a42388b2-283d-4ef4-bbba-a56ea9aae461"
	var expires time.Time
	err = legacy.QueryRowContext(ctx, `INSERT INTO mcp_oauth_grants
		(id,issuer,client_id,name,approved_by,redirect_uri,challenge,access_hash,access_until,refresh_hash)
		VALUES ($1,'issuer','client','OpenClaw','operator','redirect','challenge','access',now()+interval '10 minutes','refresh')
		RETURNING valid_until`, id).Scan(&expires)
	if err != nil {
		t.Fatal(err)
	}

	upgraded := openFresh(t, dsn)
	grants, err := upgraded.MCPGrants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ID != id || grants[0].Status != "connected" ||
		grants[0].ValidUntil == nil || !grants[0].ValidUntil.Equal(expires) {
		t.Fatalf("expected the existing pairing with expiry %s, got %+v", expires, grants)
	}
	if used, err := upgraded.UseMCP(ctx, "issuer", "access"); err != nil || used != id {
		t.Fatalf("use pre-upgrade access token: grant %q, error %v", used, err)
	}
	if err := upgraded.RefreshMCP(ctx, "issuer", "client", "refresh", "renewed-access", "renewed-refresh"); err != nil {
		t.Fatalf("rotate pre-upgrade refresh token: %v", err)
	}
	if used, err := upgraded.UseMCP(ctx, "issuer", "renewed-access"); err != nil || used != id {
		t.Fatalf("use renewed access token: grant %q, error %v", used, err)
	}
}

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
	use := func(access string) error {
		t.Helper()
		id, err := s.UseMCP(ctx, "issuer", access)
		if (err == nil && id != g.ID) || (err != nil && id != "") {
			t.Fatalf("unexpected grant %q for access check: %v", id, err)
		}
		return err
	}
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
	requireOK(use("access"))
	requireOK(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a2", "r2"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a3", "r3"))
	status("reauth_required")
	requireInactive(use("a2"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "r2", "a3", "r3"))
	requireInactive(s.SetMCPGrantExpiry(ctx, g.ID, nil))
	requireOK(s.RevokeMCP(ctx, g.ID))
	approve()
	requireOK(exchange())
	requireOK(s.SetMCPGrantExpiry(ctx, g.ID, &past))
	requireInactive(use("access"))
	requireInactive(s.RefreshMCP(ctx, "issuer", "client", "refresh", "a2", "r2"))
	status("expired")
}
