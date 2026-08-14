package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/enroll"
	"github.com/easy-waf/easy-waf/internal/store"
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

type enrollRequest struct {
	Secret   string `json:"secret"`
	Username string `json:"username"`
	Password string `json:"password"`
}

const maxLoginRequestBodyBytes int64 = 16 << 10

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	pending, err := s.Eng.Store.EnrollmentPending(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enrollment_required": pending,
		"enrollment_file":     "stateDir/secrets/enrollment",
	})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
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
			_ = s.Eng.Store.AppendAudit(r.Context(), "enrollment_rate_limited", map[string]any{
				"source_ip":   ipStr,
				"retry_after": retryAfter,
			})
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many enrollment attempts, try again later"})
			return
		}
	}

	var body enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	secret := strings.TrimSpace(body.Secret)
	user := strings.TrimSpace(body.Username)
	if user == "" {
		user = "admin"
	}
	if secret == "" || body.Password == "" {
		http.Error(w, "secret and password required", http.StatusBadRequest)
		return
	}
	if len(user) > 128 || len(body.Password) > 256 || len(secret) > 256 {
		http.Error(w, "credentials are too long", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(body.Password)) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = s.Eng.Store.ConsumeEnrollmentAndCreateUser(r.Context(), secret, user, string(hash))
	if err != nil {
		_ = s.Eng.Store.AppendAudit(r.Context(), "enrollment_failed", map[string]any{
			"source_ip": ipStr,
			"username":  user,
		})
		switch {
		case errors.Is(err, store.ErrEnrollmentSecretMismatch), errors.Is(err, store.ErrEnrollmentNotPending):
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment secret"})
		case errors.Is(err, store.ErrEnrollmentAlreadyCompleted):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "enrollment already completed"})
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	_ = enroll.RemoveFile(s.Eng.StateDir)
	_ = s.Eng.Store.AppendAudit(r.Context(), "enrollment_completed", map[string]any{
		"source_ip": ipStr,
		"username":  user,
	})
	if s.LoginRL != nil && ipStr != "" {
		s.LoginRL.RecordSuccess(ipStr)
	}

	u, err := s.Eng.Store.GetUserByUsername(r.Context(), user)
	if err != nil || u == nil {
		http.Error(w, "enrollment succeeded but session could not be issued", http.StatusInternalServerError)
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, u.SessionVersion, 24*time.Hour)
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
		pending, _ := s.Eng.Store.EnrollmentPending(r.Context())
		_ = s.Eng.Store.AppendAudit(r.Context(), "login_failed", map[string]any{
			"source_ip":           ipStr,
			"username":            user,
			"enrollment_required": pending,
		})
		if pending {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment required"})
			return
		}
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
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, u.SessionVersion, 24*time.Hour)
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
	u2, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u2 == nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u2.Username, u2.SessionVersion, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "password_changed", map[string]any{
		"username": u2.Username,
	})
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: false,
		ExpiresInSeconds:   int64((24 * time.Hour).Seconds()),
	})
}
