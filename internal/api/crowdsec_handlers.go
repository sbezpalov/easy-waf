// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/crowdsec"
)

func (s *Server) crowdsecDeleteDecision(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing decision id"})
		return
	}
	c := s.crowdsecLAPIClient()
	if err := c.DeleteDecision(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, crowdsec.ErrDecisionNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		}
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "crowdsec.decision_deleted", map[string]any{
		"decision_id": id,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) crowdsecAddDecision(w http.ResponseWriter, r *http.Request) {
	var body crowdsec.AddDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := s.crowdsecLAPIClient()
	if err := c.AddDecision(r.Context(), body); err != nil {
		switch {
		case errors.Is(err, crowdsec.ErrInvalidDecisionIP):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		}
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "crowdsec.decision_added", map[string]any{
		"ip":       body.IP,
		"type":     body.Type,
		"duration": body.Duration,
		"reason":   body.Reason,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
