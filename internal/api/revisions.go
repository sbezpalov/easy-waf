package api

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const revisionPreviewMaxRunes = 240

func revisionConfigPreview(stateDir, sha256Full string) string {
	if len(sha256Full) < 12 {
		return ""
	}
	p := filepath.Join(stateDir, "revisions", "haproxy-"+sha256Full[:12]+".cfg")
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return ""
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= revisionPreviewMaxRunes {
		return s
	}
	return string(runes[:revisionPreviewMaxRunes]) + "…"
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	curSHA, _ := s.Eng.LiveHAProxySHA256()
	out := make([]map[string]any, 0, len(revs))
	for _, rev := range revs {
		out = append(out, map[string]any{
			"id":                     rev.ID,
			"sha":                    rev.HAProxySHA256,
			"created_at":             rev.At.UTC().Format(time.RFC3339Nano),
			"is_current":             curSHA != "" && rev.HAProxySHA256 == curSHA,
			"config_snippet_preview": revisionConfigPreview(s.Eng.StateDir, rev.HAProxySHA256),
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
	err = s.Eng.Rollback(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "revision not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
