package api

import (
	"encoding/json"
	"net/http"
	"strconv"
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

const maxLoginRequestBodyBytes int64 = 16 << 10

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBodyBytes)
	ip, ipOK := clientIP(r)
	ipStr := ""
	if ipOK && ip.IsValid() {
		ipStr = ip.String()
	}
	if s.LoginRL != nil && ipStr != "" {
		allowed, retryAfter := s.LoginRL.Allow(ipStr)
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			_ = s.Eng.Store.AppendAudit(r.Context(), "login_rate_limited", map[string]any{
				"source_ip":   ipStr,
				"retry_after": retryAfter,
			})
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts, try again later"})
			return
		}
	}

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
	if len(user) > 128 || len(body.Password) > 256 {
		http.Error(w, "credentials are too long", http.StatusBadRequest)
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), user)
	if err != nil || u == nil {
		_ = s.Eng.Store.AppendAudit(r.Context(), "login_failed", map[string]any{
			"source_ip": ipStr,
			"username":  user,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
		_ = s.Eng.Store.AppendAudit(r.Context(), "login_failed", map[string]any{
			"source_ip": ipStr,
			"username":  user,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.LoginRL != nil && ipStr != "" {
		s.LoginRL.RecordSuccess(ipStr)
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
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 12)
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
