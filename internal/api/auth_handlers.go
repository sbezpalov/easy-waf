// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"github.com/easy-waf/easy-waf/internal/config"
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
	TOTPCode string `json:"totp_code,omitempty"`
}

type loginResponse struct {
	Token              string `json:"token"`
	MustChangePassword bool   `json:"must_change_password"`
	ExpiresInSeconds   int64  `json:"expires_in_seconds"`
}

type meResponse struct {
	Username           string `json:"username"`
	MustChangePassword bool   `json:"must_change_password"`
	Role               string `json:"role"`
	TOTPEnabled        bool   `json:"totp_enabled"`
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

// maxPasswordBytes is bcrypt's input limit: GenerateFromPassword refuses
// anything longer, which surfaced as a 500 instead of a validation error.
const maxPasswordBytes = 72

const errPasswordTooLong = "password must be at most 72 bytes"

// sessionTTL is how long an issued management JWT stays valid.
const sessionTTL = 8 * time.Hour

// bcryptCost is the work factor for operator password hashes.
const bcryptCost = 12

// dummyBcryptHash is compared against when the username does not exist, so that
// "unknown user" and "wrong password" take the same time. Without it the absence
// of a bcrypt comparison makes unknown usernames answer measurably faster, which
// tells an attacker which operator names are real. It is a bcrypt hash of a
// random value that no one holds.
const dummyBcryptHash = "$2a$12$C6UzMDM.H6dfI/f/IKcEe.7oJv6yEqZ4dHkPzZQeGkOTBRvCr1nWu"

// equalizeLoginTiming burns the same work as a real password check.
func equalizeLoginTiming(password string) {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	pending, err := s.Eng.Store.EnrollmentPending(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	// Public: enrollment pending flag only. The secret file path is for
	// operators via easy-waf-admin / the appliance FS, not unauthenticated clients.
	writeJSON(w, http.StatusOK, map[string]any{
		"enrollment_required": pending,
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	secret := strings.TrimSpace(body.Secret)
	user := strings.TrimSpace(body.Username)
	if user == "" {
		user = "admin"
	}
	if secret == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret and password required"})
		return
	}
	if !panelUsernameRe.MatchString(user) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username: 1-64 characters, letters, digits and . _ @ -"})
		return
	}
	if len(body.Password) > 256 || len(secret) > 256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credentials are too long"})
		return
	}
	if len(strings.TrimSpace(body.Password)) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	if len(body.Password) > maxPasswordBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errPasswordTooLong})
		return
	}

	if err := s.Eng.Store.VerifyEnrollmentSecret(r.Context(), secret); err != nil {
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
			writeInternalError(w, err)
		}
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcryptCost)
	if err != nil {
		writeInternalError(w, err)
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
			writeInternalError(w, err)
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
		writeInternalError(w, err)
		return
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, u.SessionVersion, sessionTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: false,
		ExpiresInSeconds:   int64(sessionTTL.Seconds()),
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	user := strings.TrimSpace(body.Username)
	if user == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	if len(user) > 128 || len(body.Password) > 256 || len(body.TOTPCode) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credentials are too long"})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), user)
	if err != nil || u == nil {
		// Same work as a real check: returning early here would make unknown
		// usernames answer faster and turn login into a name oracle.
		equalizeLoginTiming(body.Password)
		pending, _ := s.Eng.Store.EnrollmentPending(r.Context())
		_ = s.Eng.Store.AppendAudit(r.Context(), "login_failed", map[string]any{
			"source_ip":           ipStr,
			"username":            user,
			"enrollment_required": pending,
		})
		// "enrollment required" describes appliance-wide state that
		// GET /auth/status already returns unauthenticated, so it leaks nothing
		// extra; any other failure stays indistinguishable.
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
	if u.TOTPEnabled {
		if strings.TrimSpace(body.TOTPCode) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "totp_required"})
			return
		}
		if !s.checkSecondFactor(r.Context(), u, body.TOTPCode, ipStr) {
			_ = s.Eng.Store.AppendAudit(r.Context(), "login_failed", map[string]any{
				"source_ip": ipStr,
				"username":  user,
				"reason":    "totp",
			})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid two-factor code"})
			return
		}
	}
	tok, err := auth.SignJWT(s.JWTSecret, u.Username, u.SessionVersion, sessionTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if s.LoginRL != nil && ipStr != "" {
		s.LoginRL.RecordSuccess(ipStr)
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: u.MustChangePassword,
		ExpiresInSeconds:   int64(sessionTTL.Seconds()),
	})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if p.IsLegacyToken {
		writeJSON(w, http.StatusOK, meResponse{Username: "automation", MustChangePassword: false, Role: config.RoleAdmin})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, meResponse{Username: u.Username, MustChangePassword: u.MustChangePassword, Role: u.Role, TOTPEnabled: u.TOTPEnabled})
}

// handleLogout invalidates every session token issued to the caller.
//
// Clearing the token in the browser is not a sign-out: the JWT stays valid for
// its full TTL, so a copy taken from a shared machine or a proxy log keeps
// working. Bumping session_version revokes them all immediately.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if p.IsLegacyToken {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "legacy automation token has no session to revoke"})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := s.Eng.Store.RevokeUserSessions(r.Context(), u.ID); err != nil {
		writeInternalError(w, err)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "logout", map[string]any{
		"username": u.Username,
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBodyBytes)
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsLegacyToken {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "use local user session to change password"})
		return
	}
	// current_password is checked here too, so this endpoint gets the same
	// per-IP limiter as login instead of offering an unthrottled oracle.
	if ip, ipOK := clientIP(r); ipOK && ip.IsValid() && s.LoginRL != nil {
		if allowed, retryAfter := s.LoginRL.Allow(ip.String()); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
			return
		}
	}
	var body changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if len(strings.TrimSpace(body.NewPassword)) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password must be at least 8 characters"})
		return
	}
	if len(body.NewPassword) > maxPasswordBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errPasswordTooLong})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.CurrentPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password incorrect"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcryptCost)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := s.Eng.Store.UpdateUserPassword(r.Context(), u.ID, string(hash), false); err != nil {
		writeInternalError(w, err)
		return
	}
	u2, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u2 == nil {
		writeInternalError(w, err)
		return
	}
	if ip, ipOK := clientIP(r); ipOK && ip.IsValid() && s.LoginRL != nil {
		s.LoginRL.RecordSuccess(ip.String())
	}
	tok, err := auth.SignJWT(s.JWTSecret, u2.Username, u2.SessionVersion, sessionTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "password_changed", map[string]any{
		"username": u2.Username,
	})
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              tok,
		MustChangePassword: false,
		ExpiresInSeconds:   int64(sessionTTL.Seconds()),
	})
}
