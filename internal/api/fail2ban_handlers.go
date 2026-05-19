package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/fail2ban"
)

func (s *Server) fail2banOverview(w http.ResponseWriter, r *http.Request) {
	c := fail2ban.DefaultClient()
	ov, err := c.Overview(r.Context())
	if err != nil {
		if errors.Is(err, fail2ban.ErrNotInstalled) {
			writeJSON(w, http.StatusOK, ov)
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "status": ov.Status})
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) fail2banJailStatus(w http.ResponseWriter, r *http.Request) {
	jail := chi.URLParam(r, "jail")
	c := fail2ban.DefaultClient()
	js, err := c.JailStatus(r.Context(), jail)
	if err != nil {
		switch {
		case errors.Is(err, fail2ban.ErrInvalidJail):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusOK, js)
}

func (s *Server) fail2banUnban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := fail2ban.DefaultClient()
	if err := c.UnbanIP(r.Context(), body.Jail, body.IP); err != nil {
		switch {
		case errors.Is(err, fail2ban.ErrInvalidJail), errors.Is(err, fail2ban.ErrInvalidIP):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		}
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "fail2ban.unban", map[string]any{
		"jail": body.Jail,
		"ip":   body.IP,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
