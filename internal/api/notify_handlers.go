// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/easy-waf/easy-waf/internal/notify"
)

// notifyTest serves POST /notify/test: one test message to every configured channel.
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	gs := s.Eng.Settings()
	if !notify.Enabled(gs) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no notification channel is configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := notify.Send(ctx, gs, notify.Event{
		Kind:     "test",
		Severity: notify.SeverityInfo,
		Title:    "Test notification",
		Text:     "Notifications from this appliance reach you.",
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
