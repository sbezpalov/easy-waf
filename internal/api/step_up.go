// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/easy-waf/easy-waf/internal/auth"
)

// stepUpWindow is how long a password confirmation unlocks operations that run
// as root on the host. A stolen session token alone cannot reach them.
const stepUpWindow = 5 * time.Minute

type confirmRequest struct {
	Password string `json:"password"`
}

type confirmResponse struct {
	Token                  string `json:"token"`
	ExpiresInSeconds       int64  `json:"expires_in_seconds"`
	StepUpExpiresInSeconds int64  `json:"step_up_expires_in_seconds"`
}

// handleConfirmPassword swaps the caller's session token for one that records
// this confirmation. The mark lives in the token, not on the account, so one
// session confirming does nothing for another. The session's expiry is kept.
func (s *Server) handleConfirmPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBodyBytes)
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsLegacyToken {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "use local user session to confirm a password"})
		return
	}
	ip, ipOK := clientIP(r)
	limited := ipOK && ip.IsValid() && s.LoginRL != nil
	if limited {
		if allowed, retryAfter := s.LoginRL.Allow(ip.String()); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
			return
		}
	}
	var body confirmRequest
	if err := decodeJSONRequest(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
		_ = s.Eng.Store.AppendAudit(r.Context(), "step_up_failed", map[string]any{"username": u.Username})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password incorrect"})
		return
	}
	now := time.Now()
	tok, err := auth.SignStepUpJWT(s.JWTSecret, u.Username, u.SessionVersion, p.ExpiresAt, now)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if limited {
		s.LoginRL.RecordSuccess(ip.String())
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "step_up_granted", map[string]any{"username": u.Username})
	writeJSON(w, http.StatusOK, confirmResponse{
		Token:                  tok,
		ExpiresInSeconds:       int64(p.ExpiresAt.Sub(now).Seconds()),
		StepUpExpiresInSeconds: int64(stepUpWindow.Seconds()),
	})
}
