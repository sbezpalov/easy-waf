// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log"
	"net/http"
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

func writeApplicationChanged(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]string{
		"code":  "application_changed",
		"error": "The publication changed or was deleted. Reload its settings before continuing.",
	})
}
