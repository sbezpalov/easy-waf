// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// seedAudit appends n rows whose action carries a marker unique to the test,
// so filtering on it isolates them from rows other tests share the table with.
func seedAudit(t *testing.T, st *Store, n int) string {
	t.Helper()
	ctx := context.Background()
	marker := fmt.Sprintf("r9test-%d", time.Now().UnixNano())
	for i := 0; i < n; i++ {
		action := fmt.Sprintf("POST /api/v1/%s/item-%d", marker, i)
		if i%3 == 0 {
			action = marker + " rare"
		}
		if err := st.AppendAudit(ctx, action, map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = st.db.ExecContext(context.Background(), `DELETE FROM audit_log WHERE action LIKE '%' || $1 || '%'`, marker)
	})
	return marker
}

// Keyset pages cover every matching row exactly once, newest first, and
// has_more is false only on the last page.
func TestListAuditLogs_KeysetPaging(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	marker := seedAudit(t, st, 12)

	var seen []int64
	var before int64
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("paging did not terminate")
		}
		got, more, err := st.ListAuditLogs(ctx, AuditListParams{Limit: 5, Action: marker, BeforeID: before})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range got {
			seen = append(seen, e.ID)
		}
		if !more {
			if len(got) == 0 && page > 0 {
				t.Fatal("has_more was true before an empty page")
			}
			break
		}
		if len(got) != 5 {
			t.Fatalf("page %d: %d rows with has_more", page, len(got))
		}
		before = got[len(got)-1].ID
	}
	if len(seen) != 12 {
		t.Fatalf("saw %d rows, want 12", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] >= seen[i-1] {
			t.Fatalf("not strictly newest first at %d: %v", i, seen)
		}
	}
}

func TestListAuditLogs_FiltersAndCount(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	marker := seedAudit(t, st, 12) // 4 "rare", 8 item rows

	p := AuditListParams{Limit: 100, Action: marker + " rare"}
	got, more, err := st.ListAuditLogs(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || more {
		t.Fatalf("rare filter: %d rows, more=%v", len(got), more)
	}
	n, err := st.CountAuditLogs(ctx, p)
	if err != nil || n != 4 {
		t.Fatalf("count: %d %v", n, err)
	}

	// The count honors the cursor like the list does.
	p.BeforeID = got[1].ID
	if n, err := st.CountAuditLogs(ctx, p); err != nil || n != 2 {
		t.Fatalf("count before cursor: %d %v", n, err)
	}

	// Time bounds: everything was written just now.
	future := time.Now().Add(time.Hour)
	got, _, err = st.ListAuditLogs(ctx, AuditListParams{Action: marker, From: &future})
	if err != nil || len(got) != 0 {
		t.Fatalf("from in the future: %d rows %v", len(got), err)
	}
	past := time.Now().Add(-time.Hour)
	got, _, err = st.ListAuditLogs(ctx, AuditListParams{Action: marker, From: &past, To: &future})
	if err != nil || len(got) != 12 {
		t.Fatalf("within bounds: %d rows %v", len(got), err)
	}

	// Offset paging still works for existing API clients.
	got, more, err = st.ListAuditLogs(ctx, AuditListParams{Action: marker, Limit: 5, Offset: 10})
	if err != nil || len(got) != 2 || more {
		t.Fatalf("offset 10: %d rows more=%v %v", len(got), more, err)
	}
}

func TestAuditWhere_OnlySetFilters(t *testing.T) {
	where, args := auditWhere(AuditListParams{})
	if where != "" || len(args) != 0 {
		t.Fatalf("no filters: %q %v", where, args)
	}
	where, args = auditWhere(AuditListParams{Action: " apply ", BeforeID: 7})
	want := " WHERE action ILIKE '%' || $1 || '%' AND id < $2"
	if where != want || len(args) != 2 || args[0] != "apply" || args[1] != int64(7) {
		t.Fatalf("got %q %v", where, args)
	}
}
