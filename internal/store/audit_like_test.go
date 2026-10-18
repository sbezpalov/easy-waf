// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestListAuditLogs_ActionFilterIsLiteral(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	marker := fmt.Sprintf("liketest%d", time.Now().UnixNano())
	for _, a := range []string{marker + "_x", marker + "Ax", marker + "%y"} {
		if err := st.AppendAudit(ctx, a, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = st.db.ExecContext(context.Background(), `DELETE FROM audit_log WHERE position($1 in action) > 0`, marker)
	})
	for filter, want := range map[string]int{marker + "_x": 1, marker + "%": 1, marker: 3} {
		got, _, err := st.ListAuditLogs(ctx, AuditListParams{Action: filter, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != want {
			t.Errorf("filter %q matched %d rows, want %d", filter, len(got), want)
		}
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`a_b%c\d`); got != `a\_b\%c\\d` {
		t.Fatalf("escapeLike = %q", got)
	}
}
