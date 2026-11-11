// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

var panelUsernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type panelUserJSON struct {
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
}

// temporaryPassword is shown once; the user must change it at first sign-in.
func temporaryPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

func (s *Server) listPanelUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Eng.Store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]panelUserJSON, 0, len(list))
	for _, u := range list {
		out = append(out, panelUserJSON{Username: u.Username, Role: u.Role, MustChangePassword: u.MustChangePassword, CreatedAt: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")})
	}
	writeJSON(w, http.StatusOK, out)
}

type panelUserBody struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Server) createPanelUser(w http.ResponseWriter, r *http.Request) {
	var body panelUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if !panelUsernameRe.MatchString(body.Username) {
		http.Error(w, "username: 1-64 characters, letters, digits and . _ @ -", http.StatusBadRequest)
		return
	}
	if !config.ValidRole(body.Role) {
		http.Error(w, "role must be admin or viewer", http.StatusBadRequest)
		return
	}
	if u, err := s.Eng.Store.GetUserByUsername(r.Context(), body.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if u != nil {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}
	pass, err := temporaryPassword()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcryptCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := config.AdminUser{Username: body.Username, PasswordHash: string(hash), MustChangePassword: true, Role: body.Role}
	if err := s.Eng.Store.CreateUser(r.Context(), &u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "panel_user_created", map[string]any{"username": u.Username, "role": u.Role})
	writeJSON(w, http.StatusCreated, map[string]string{"username": u.Username, "role": u.Role, "temporary_password": pass})
}

func (s *Server) patchPanelUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "username")
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !config.ValidRole(body.Role) {
		http.Error(w, "role must be admin or viewer", http.StatusBadRequest)
		return
	}
	if !writePanelUserErr(w, s.Eng.Store.SetUserRole(r.Context(), name, body.Role)) {
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "panel_user_role_changed", map[string]any{"username": name, "role": body.Role})
	writeJSON(w, http.StatusOK, map[string]string{"username": name, "role": body.Role})
}

func (s *Server) resetPanelUserPassword(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "username")
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if u == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pass, err := temporaryPassword()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcryptCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Also ends the user's sessions: UpdateUserPassword bumps session_version.
	if err := s.Eng.Store.UpdateUserPassword(r.Context(), u.ID, string(hash), true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "panel_user_password_reset", map[string]any{"username": name})
	writeJSON(w, http.StatusOK, map[string]string{"username": name, "temporary_password": pass})
}

func (s *Server) deletePanelUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "username")
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsLegacyToken && p.Username == name {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	if !writePanelUserErr(w, s.Eng.Store.DeleteUser(r.Context(), name)) {
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "panel_user_deleted", map[string]any{"username": name})
	w.WriteHeader(http.StatusNoContent)
}

func writePanelUserErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, store.ErrLastAdmin):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return false
}
