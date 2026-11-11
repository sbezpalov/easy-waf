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
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	gs := e.Settings()
	if !notify.Enabled(gs) {
		return
	}
	msg := err.Error()
	if len(msg) > notifyApplyErrMax {
		msg = msg[:notifyApplyErrMax] + "..."
	}
	ev := notify.Event{
		Kind:     "apply_failed",
		Severity: notify.SeverityCritical,
		Title:    "HAProxy apply failed",
		Text:     fmt.Sprintf("Change %q was not applied; the edge keeps its previous configuration.\n%s", label, msg),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := notify.Send(ctx, gs, ev); err != nil {
			log.Printf("notify: apply failure: %v", err)
		}
	}()
}
