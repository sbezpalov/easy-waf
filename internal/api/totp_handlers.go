// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
)

const totpIssuer = "Easy Home WAF"

// checkSecondFactor accepts a current TOTP code (each step once) or an unused recovery code.
func (s *Server) checkSecondFactor(ctx context.Context, u *config.AdminUser, code, ip string) bool {
	code = strings.TrimSpace(code)
	if auth.IsTOTPCode(code) {
		step, ok := auth.VerifyTOTP(u.TOTPSecret, code, time.Now(), u.TOTPLastStep)
		if !ok {
			return false
		}
		used, err := s.Eng.Store.UseTOTPStep(ctx, u.ID, step)
		return err == nil && used
	}
	remaining, ok, err := s.Eng.Store.UseRecoveryCode(ctx, u.ID, auth.HashRecoveryCode(code))
	if err != nil || !ok {
		return false
	}
	_ = s.Eng.Store.AppendAudit(ctx, "totp_recovery_code_used", map[string]any{"username": u.Username, "source_ip": ip, "remaining": remaining})
	return true
}

func (s *Server) sessionUser(w http.ResponseWriter, r *http.Request) *config.AdminUser {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsLegacyToken {
		http.Error(w, "two-factor sign-in applies to panel users only", http.StatusBadRequest)
		return nil
	}
	u, err := s.Eng.Store.GetUserByUsername(r.Context(), p.Username)
	if err != nil || u == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return u
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	if u.TOTPEnabled {
		http.Error(w, "two-factor sign-in is already on; turn it off first", http.StatusConflict)
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.Eng.Store.SetTOTPPending(r.Context(), u.Username, secret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": auth.TOTPURI(totpIssuer, u.Username, secret)})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pending, err := s.Eng.Store.GetTOTPPending(r.Context(), u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pending == "" {
		http.Error(w, "start the setup first", http.StatusBadRequest)
		return
	}
	step, ok := auth.VerifyTOTP(pending, strings.TrimSpace(body.Code), time.Now(), 0)
	if !ok {
		http.Error(w, "wrong code; check that the phone's clock is correct", http.StatusBadRequest)
		return
	}
	codes, err := auth.GenerateRecoveryCodes(10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, auth.HashRecoveryCode(c))
	}
	if err := s.Eng.Store.EnableTOTP(r.Context(), u.Username, pending, step, hashes); err != nil {
		http.Error(w, "setup changed meanwhile; start again", http.StatusConflict)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "totp_enabled", map[string]any{"username": u.Username})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	if err := s.Eng.Store.DisableTOTP(r.Context(), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "totp_disabled", map[string]any{"username": u.Username})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetPanelUserTOTP(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "username")
	if !writePanelUserErr(w, s.Eng.Store.DisableTOTP(r.Context(), name)) {
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "panel_user_totp_reset", map[string]any{"username": name})
	w.WriteHeader(http.StatusNoContent)
}
