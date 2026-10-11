// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	user := strings.TrimSpace(q.Get("user"))
	action := strings.TrimSpace(q.Get("action"))
	if strings.EqualFold(action, "all") {
		action = ""
	}
	var beforeID int64
	if v := strings.TrimSpace(q.Get("before_id")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			http.Error(w, "invalid before_id (positive integer)", http.StatusBadRequest)
			return
		}
		beforeID = n
	}
	var fromPtr, toPtr *time.Time
	if v := strings.TrimSpace(q.Get("from")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid from (use RFC3339)", http.StatusBadRequest)
			return
		}
		fromPtr = &t
	}
	if v := strings.TrimSpace(q.Get("to")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid to (use RFC3339)", http.StatusBadRequest)
			return
		}
		toPtr = &t
	}
	p := store.AuditListParams{
		Limit:    limit,
		Offset:   offset,
		BeforeID: beforeID,
		User:     user,
		Action:   action,
		From:     fromPtr,
		To:       toPtr,
	}
	if p.Limit <= 0 {
		p.Limit = 100
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	entries, hasMore, err := s.Eng.Store.ListAuditLogs(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []config.AuditLogEntry{}
	}
	resp := map[string]any{
		"entries":  entries,
		"limit":    p.Limit,
		"offset":   p.Offset,
		"has_more": hasMore,
	}
	if hasMore {
		// Pass back as before_id for the next page.
		resp["next_before_id"] = entries[len(entries)-1].ID
	}
	// An exact total reads every matching row (up to ~0.6 s on 2M rows) and
	// used to run on every page and every 15 s auto-refresh; it is now opt-in.
	if v := strings.TrimSpace(q.Get("include_total")); v == "1" || strings.EqualFold(v, "true") {
		total, err := s.Eng.Store.CountAuditLogs(r.Context(), p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp["total"] = total
	}
	writeJSON(w, http.StatusOK, resp)
}
