// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAppliedErrorPreservesOutcomeAndCause(t *testing.T) {
	err := appliedOperationError(true, context.DeadlineExceeded)
	wrapped := errors.Join(errors.New("cleanup failure"), fmt.Errorf("operation: %w", err))
	var applied *AppliedError
	if !errors.As(wrapped, &applied) || !errors.Is(wrapped, context.DeadlineExceeded) {
		t.Fatalf("applied state or deadline lost through wrappers: %v", wrapped)
	}
	if got := appliedOperationError(false, context.Canceled); got != context.Canceled {
		t.Fatalf("rejected operation was tagged as applied: %v", got)
	}
	if got := appliedOperationError(true, nil); got != nil {
		t.Fatalf("successful operation gained an error: %v", got)
	}
}

func TestApplyFailureEventReportsAppliedStateEvenAfterCancellation(t *testing.T) {
	ev, ok := applyFailureEvent("update", &AppliedError{Err: context.Canceled})
	if !ok || !strings.Contains(ev.Title, "applied with errors") || !strings.Contains(ev.Text, "is applied") || !strings.Contains(ev.Text, "Saved settings remain") {
		t.Fatalf("applied state lost in notification: %+v, emitted=%v", ev, ok)
	}
	if strings.Contains(ev.Text, "was not applied") || strings.Contains(ev.Text, "keeps its previous") {
		t.Fatalf("notification falsely claims the previous configuration: %s", ev.Text)
	}
	if _, ok := applyFailureEvent("canceled", context.Canceled); ok {
		t.Fatal("ordinary cancellation emitted a failure event")
	}
}

func TestApplyFailureEventDoesNotAssumeRecoverySucceeded(t *testing.T) {
	ev, ok := applyFailureEvent("update", errors.New("restoring artifacts failed"))
	if !ok || !strings.Contains(ev.Text, "Check the current edge status") || strings.Contains(ev.Text, "keeps its previous") {
		t.Fatalf("notification assumes an unproven recovery: %+v, emitted=%v", ev, ok)
	}
}
