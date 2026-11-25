// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/network"
	"github.com/easy-waf/easy-waf/internal/host/runner"
	"github.com/easy-waf/easy-waf/internal/mgmttls"
)

func (s *Server) hostGetHostname(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name, err := network.Hostname(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hostname": name})
}

func (s *Server) hostPutHostname(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname string `json:"hostname"`
	}
	if err := decodeJSONRequest(r, &body); err != nil || !hostspec.ValidHostName(body.Hostname) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a lowercase DNS hostname of up to 64 characters."})
		return
	}
	if _, err := runner.Privileged(r.Context(), "hostname-set", body.Hostname); err != nil {
		writeInternalError(w, err)
		return
	}
	s.hostAppendAudit(r.Context(), "host_hostname_set", map[string]any{"hostname": body.Hostname}, false)
	s.hostGetHostname(w, r)
}

func (s *Server) managementIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || s.MgmtTLS == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Open the panel over HTTPS to manage its DNS identity."})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.MgmtTLS.Identity())
	case http.MethodDelete:
		if err := s.MgmtTLS.RemoveIdentity(s.MgmtTLSCertPath, r.Header.Get("X-Identity-SHA256")); err != nil {
			writeIdentityError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		var body struct {
			Hostname string `json:"hostname"`
			Renew    bool   `json:"renew"`
		}
		if err := decodeJSONRequest(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid identity request."})
			return
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(body.Hostname), "."))
		if !hostspec.ValidManagementName(name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a DNS hostname without a port, IP address or wildcard."})
			return
		}
		info, err := s.MgmtTLS.SetIdentity(s.MgmtTLSCertPath, name, r.Header.Get("X-Identity-SHA256"), body.Renew)
		if err != nil {
			writeIdentityError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func writeIdentityError(w http.ResponseWriter, err error) {
	if errors.Is(err, mgmttls.ErrIdentityChanged) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeInternalError(w, err)
}
