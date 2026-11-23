// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestApplyRulesetWithRollbackRejectsInclude(t *testing.T) {
	_, _, err := ApplyRulesetWithRollback(t.Context(), `include "other.nft"`, 90)
	if err == nil || !strings.Contains(err.Error(), "must not use include") {
		t.Fatalf("expected local validation error for include, got %v", err)
	}
}

func TestCommitRuleset_invalidToken(t *testing.T) {
	if err := CommitRuleset(context.Background(), "not-hex-token!"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
