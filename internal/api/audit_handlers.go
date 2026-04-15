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
		Limit:  limit,
		Offset: offset,
		User:   user,
		Action: action,
		From:   fromPtr,
		To:     toPtr,
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
	entries, err := s.Eng.Store.ListAuditLogs(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	total, err := s.Eng.Store.CountAuditLogs(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []config.AuditLogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   p.Limit,
		"offset":  p.Offset,
	})
}
