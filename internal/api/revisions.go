// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/diagnostics"
)

const revisionPreviewMaxRunes = 240

func revisionConfigPreview(b []byte, truncated bool) string {
	if len(b) == 0 {
		return ""
	}
	b = diagnostics.MaskHAProxyConfigContent(b)
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) > revisionPreviewMaxRunes {
		return string(runes[:revisionPreviewMaxRunes]) + "…"
	}
	if truncated {
		return s + "…"
	}
	return s
}

func (s *Server) listRevisions(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	revs, err := s.Eng.Store.ListConfigRevisions(r.Context(), limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	curSHA, _ := s.Eng.LiveHAProxySHA256()
	out := make([]map[string]any, 0, len(revs))
	for _, rev := range revs {
		prefix, truncated := s.Eng.RevisionPreview(rev.HAProxySHA256)
		out = append(out, map[string]any{
			"id":                     rev.ID,
			"sha":                    rev.HAProxySHA256,
			"label":                  rev.Label,
			"created_at":             rev.At.UTC().Format(time.RFC3339Nano),
			"is_current":             curSHA != "" && rev.HAProxySHA256 == curSHA,
			"config_snippet_preview": revisionConfigPreview(prefix, truncated),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) postRevisionRollback(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid revision id", http.StatusBadRequest)
		return
	}
	ctx, cancel := applyContext(r.Context())
	defer cancel()
	err = s.Eng.Rollback(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "revision not found", http.StatusNotFound)
			return
		}
		writeApplyRejected(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
