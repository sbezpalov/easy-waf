// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestAppliedFailureNeverUndoesSavedChange(t *testing.T) {
	cause := context.DeadlineExceeded
	for _, err := range []error{
		&engine.AppliedError{Err: cause},
		fmt.Errorf("request: %w", &engine.AppliedError{Err: cause}),
		errors.Join(errors.New("release lock failed"), &engine.AppliedError{Err: cause}),
	} {
		undone := false
		got := undoRejectedApply(t.Context(), err, func(context.Context) error {
			undone = true
			return nil
		})
		if undone {
			t.Fatalf("undid an already-applied change: %v", err)
		}
		if got != err || !errors.Is(got, cause) {
			t.Fatalf("applied result/cause was lost: %v", got)
		}
	}
}

func TestRejectedApplyCompensatesWithFreshContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cause := errors.New("validation failed")
	undone := false
	got := undoRejectedApply(ctx, cause, func(ctx context.Context) error {
		undone = true
		if err := ctx.Err(); err != nil {
			t.Fatalf("undo inherited spent request context: %v", err)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > undoTimeout || time.Until(deadline) <= 0 {
			t.Fatal("undo has no bounded fresh budget")
		}
		return nil
	})
	if !undone || !errors.Is(got, cause) || !strings.Contains(got.Error(), "change not saved") {
		t.Fatalf("rejected change did not compensate correctly: %v", got)
	}
}

func TestAppliedFailureResponseReportsKeptConfiguration(t *testing.T) {
	cause := fmt.Errorf("internal-database-detail: %w", context.DeadlineExceeded)
	rec := httptest.NewRecorder()
	writeApplyRejected(rec, &engine.AppliedError{Err: cause})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "configuration applied") {
		t.Fatalf("applied change reported as rejection: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "internal-database-detail") || strings.Contains(rec.Body.String(), "apply timed out") {
		t.Fatalf("internal cause leaked or applied result masked: %s", rec.Body.String())
	}
}
