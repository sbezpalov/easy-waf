// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestListAudit_RejectsBadBeforeID(t *testing.T) {
	s := &Server{}
	for _, v := range []string{"abc", "0", "-5"} {
		rec := httptest.NewRecorder()
		s.listAudit(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit?before_id="+v, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("before_id=%s: status %d", v, rec.Code)
		}
	}
}

type auditPage struct {
	Entries      []config.AuditLogEntry `json:"entries"`
	HasMore      bool                   `json:"has_more"`
	NextBeforeID *int64                 `json:"next_before_id"`
	Total        *int64                 `json:"total"`
}

func getAuditPage(t *testing.T, s *Server, query string) auditPage {
	t.Helper()
	rec := httptest.NewRecorder()
	s.listAudit(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit?"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", query, rec.Code, rec.Body.String())
	}
	var p auditPage
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// Pages follow next_before_id to the end; the exact total is only computed
// when asked for.
func TestListAudit_CursorAndOptionalTotal(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	marker := fmt.Sprintf("r9api-%d", time.Now().UnixNano())
	for i := 0; i < 7; i++ {
		if err := st.AppendAudit(ctx, marker, nil); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Eng: engine.New(t.TempDir(), st, config.GlobalSettings{})}

	first := getAuditPage(t, s, "action="+marker+"&limit=3")
	if len(first.Entries) != 3 || !first.HasMore || first.NextBeforeID == nil {
		t.Fatalf("first page: %+v", first)
	}
	if first.Total != nil {
		t.Fatal("total computed without include_total")
	}
	if *first.NextBeforeID != first.Entries[2].ID {
		t.Fatalf("next_before_id %d, want last id %d", *first.NextBeforeID, first.Entries[2].ID)
	}
	second := getAuditPage(t, s, fmt.Sprintf("action=%s&limit=3&before_id=%d", marker, *first.NextBeforeID))
	third := getAuditPage(t, s, fmt.Sprintf("action=%s&limit=3&before_id=%d", marker, *second.NextBeforeID))
	if len(second.Entries) != 3 || len(third.Entries) != 1 || third.HasMore || third.NextBeforeID != nil {
		t.Fatalf("second %d rows, third %+v", len(second.Entries), third)
	}

	withTotal := getAuditPage(t, s, "action="+marker+"&limit=3&include_total=1")
	if withTotal.Total == nil || *withTotal.Total != 7 {
		t.Fatalf("total: %v", withTotal.Total)
	}
}
