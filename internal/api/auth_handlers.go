package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token              string `json:"token"`
	MustChangePassword bool   `json:"must_change_password"`
	ExpiresInSeconds   int64  `json:"expires_in_seconds"`
}

type meResponse struct {
	Username           string `json:"username"`
	MustChangePassword bool   `json:"must_change_password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(body.Username)
	if user == "" || body.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), user)
	if err != nil || u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: u.MustChangePassword,
		ExpiresInSeconds:   int64((24 * time.Hour).Seconds()),
	})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.IsLegacyToken {
		writeJSON(w, http.StatusOK, meResponse{Username: "automation", MustChangePassword: false})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, meResponse{Username: u.Username, MustChangePassword: u.MustChangePassword})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsLegacyToken {
		http.Error(w, "use local user session to change password", http.StatusBadRequest)
		return
	}
	var body changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(body.NewPassword)) < 8 {
		http.Error(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.CurrentPassword)) != nil {
		http.Error(w, "current password incorrect", http.StatusUnauthorized)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.Eng.Store.UpdateUserPassword(r.Context(), u.ID, string(hash), false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: false,
		ExpiresInSeconds:   int64((24 * time.Hour).Seconds()),
	})
}
