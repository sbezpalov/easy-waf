// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/easy-waf/easy-waf/internal/notify"
)

const notifyApplyErrMax = 1500

// notifyApplyFailure reports a failed apply in the background: delivery must
// not delay or change the caller's result.
func (e *Engine) notifyApplyFailure(label string, err error) {
	ev, ok := applyFailureEvent(label, err)
	if !ok {
		return
	}
	gs := e.Settings()
	if !notify.Enabled(gs) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := notify.Send(ctx, gs, ev); err != nil {
			log.Printf("notify: apply failure: %v", err)
		}
	}()
}

func applyFailureEvent(label string, err error) (notify.Event, bool) {
	if err == nil {
		return notify.Event{}, false
	}
	var applied *AppliedError
	wasApplied := errors.As(err, &applied)
	if !wasApplied && errors.Is(err, context.Canceled) {
		return notify.Event{}, false
	}
	msg := err.Error()
	if len(msg) > notifyApplyErrMax {
		msg = msg[:notifyApplyErrMax] + "..."
	}
	ev := notify.Event{
		Kind:     "apply_failed",
		Severity: notify.SeverityCritical,
		Title:    "HAProxy apply failed",
		Text:     fmt.Sprintf("Applying change %q failed. Check the current edge status and error before retrying.\n%s", label, msg),
	}
	if wasApplied {
		ev.Title = "HAProxy change applied with errors"
		ev.Text = fmt.Sprintf("Change %q is applied, but a later step failed. Saved settings remain in place.\n%s", label, msg)
	}
	return ev, true
}
