// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/config"
)

func (s *Server) beginApplicationMutation(w http.ResponseWriter, r *http.Request) (*http.Request, func(), bool) {
	ctx, release, err := s.Eng.LockApplicationMutation(r.Context())
	if err != nil {
		writeApplyRejected(w, err)
		return r, nil, false
	}
	return r.WithContext(ctx), func() {
		if err := release(); err != nil {
			log.Printf("api: release application mutation lock: %v", err)
		}
	}, true
}

// beginExistingApplicationMutation loads the row with its optional revision
// precondition under the same lock held for the write and Apply.
func (s *Server) beginExistingApplicationMutation(w http.ResponseWriter, r *http.Request) (*http.Request, config.Application, func(), bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query string", http.StatusBadRequest)
		return r, config.Application{}, nil, false
	}
	var expected *time.Time
	if values, supplied := query["expected_updated_at"]; supplied {
		rev, err := time.Parse(time.RFC3339Nano, query.Get("expected_updated_at"))
		if len(values) != 1 || err != nil || rev.IsZero() {
			http.Error(w, "expected_updated_at must be one nonzero RFC3339 timestamp", http.StatusBadRequest)
			return r, config.Application{}, nil, false
		}
		expected = &rev
	}
	r, release, ok := s.beginApplicationMutation(w, r)
	if !ok {
		return r, config.Application{}, nil, false
	}
	a, ok := s.loadApplicationVersion(w, r, chi.URLParam(r, "id"), expected)
	if !ok {
		release()
		return r, config.Application{}, nil, false
	}
	return r, a, release, true
}

func writeApplicationChanged(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]string{
		"code":  "application_changed",
		"error": "The publication changed or was deleted. Reload its settings before continuing.",
	})
}
