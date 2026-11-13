// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyRejectsInvalidLabelBeforeAccessingState(t *testing.T) {
	for _, label := range []string{"invalid\x00label", "invalid\xfflabel"} {
		for _, onlyIfChanged := range []bool{false, true} {
			name := "apply"
			if onlyIfChanged {
				name = "if-changed"
			}
			t.Run(name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("invalid label reached state access: %v", r)
					}
				}()
				// Any attempt to use the store would panic. Rejected metadata must
				// not fetch feeds, acquire locks or touch state first.
				e := &Engine{}
				var err error
				if onlyIfChanged {
					var applied bool
					applied, err = e.ApplyIfChanged(t.Context(), label)
					if applied {
						t.Fatal("invalid label reported an applied configuration")
					}
				} else {
					err = e.Apply(t.Context(), label)
				}
				var appliedErr *AppliedError
				if err == nil || !strings.Contains(err.Error(), "label") || errors.As(err, &appliedErr) {
					t.Fatalf("expected early label rejection: %v", err)
				}
			})
		}
	}
}
