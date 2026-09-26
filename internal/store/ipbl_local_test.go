// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// An entry added without a note is stored as NULL; listing must still work,
// or every later apply fails while rendering the blacklist map.
func TestListIPBLLocalWithoutNote(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	e := config.IPBLLocalEntry{CIDR: "198.51.100.77/32", Enabled: true}
	if err := st.UpsertIPBLLocal(ctx, &e); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteIPBLLocal(context.Background(), e.ID) })
	all, err := st.ListIPBLLocal(ctx)
	if err != nil {
		t.Fatalf("ListIPBLLocal with a NULL note: %v", err)
	}
	for _, got := range all {
		if got.ID == e.ID {
			if got.Note != "" {
				t.Fatalf("note: %q", got.Note)
			}
			return
		}
	}
	t.Fatal("entry not listed")
}
