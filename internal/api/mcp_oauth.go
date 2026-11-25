// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/easy-waf/easy-waf/internal/mcpd"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const diagnosticsScope = "diagnostics:read"
const resourceMeta = "/.well-known/oauth-protected-resource/mcp"

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var raw64 = base64.RawURLEncoding

type registration struct {
	Name      string   `json:"client_name"`
	Redirects []string `json:"redirect_uris"`
	Method    string   `json:"token_endpoint_auth_method"`
}

func validCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 1024 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.ContainsAny(raw, "\\\r\n") {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (net.ParseIP(u.Hostname()).IsLoopback() || u.Hostname() == "localhost"))
}

func digest(s string) string { sum := sha256.Sum256([]byte(s)); return raw64.EncodeToString(sum[:]) }
func newSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read always fills the buffer or terminates.
	return raw64.EncodeToString(b[:])
}
func issuer(r *http.Request) string { return "https://" + r.Host }

func (s *Server) oauthAvailable(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || s.mcpTransport == nil || s.Eng.Store == nil || len(s.JWTSecret) < 32 {
		http.NotFound(w, r)
		return false
	}
	return true
}

// Registrations carry only public metadata. A domain-separated MAC avoids storing
// anonymous registrations and binds the callback and name to this issuer.
func (s *Server) registrationMAC(origin, payload string) []byte {
	mac := hmac.New(sha256.New, s.JWTSecret)
	_, _ = mac.Write([]byte("mcp-registration\x00" + origin + "\x00" + payload))
	return mac.Sum(nil)
}

// diagnosticTransport dispatches SDK-generated GETs only to the private read-only
// router. No client-selected authority, credentials or network dial is involved.
type diagnosticTransport struct{ reads http.Handler }

func (d diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	// Start a fresh route match while retaining cancellation from the MCP call.
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, (*chi.Context)(nil))
	d.reads.ServeHTTP(w, r.WithContext(ctx))
	return w.Result(), nil
}
func (s *Server) managementMCPTransport() http.Handler {
	reads := chi.NewRouter()
	reads.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.serveAuditedDiagnostic(next, w, r, "")
		})
	})
	reads.Route("/api/v1/mcp/diagnostics", s.mountDiagnosticReads)
	return mcpd.ManagementHandler(diagnosticTransport{reads})
}

func (s *Server) mountOAuth(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !s.oauthAvailable(w, r) {
					return
				}
				if origin := r.Header.Get("Origin"); origin != "" && origin != issuer(r) {
					http.Error(w, "origin rejected", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Get(resourceMeta, func(w http.ResponseWriter, r *http.Request) {
			o := issuer(r)
			writeJSON(w, http.StatusOK, map[string]any{"resource": o + "/mcp", "authorization_servers": []string{o}, "scopes_supported": []string{diagnosticsScope}})
		})
		r.Get("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
			o := issuer(r)
			writeJSON(w, http.StatusOK, map[string]any{"issuer": o, "registration_endpoint": o + "/oauth/register", "authorization_endpoint": o + "/oauth/authorize", "token_endpoint": o + "/oauth/token", "scopes_supported": []string{diagnosticsScope}, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}})
		})
		r.Post("/oauth/register", s.oauthRegister)
		r.Get("/oauth/authorize", s.oauthAuthorize)
		r.Post("/oauth/token", s.oauthToken)
		r.HandleFunc("/mcp", s.oauthResource)
	})
}

func (s *Server) oauthRegister(w http.ResponseWriter, r *http.Request) {
	var c registration
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&c) != nil || strings.TrimSpace(c.Name) == "" || len(c.Name) > 100 || len(c.Redirects) != 1 || !validCallback(c.Redirects[0]) || c.Method != "none" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	b, _ := json.Marshal(c)
	payload := raw64.EncodeToString(b)
	id := payload + "." + raw64.EncodeToString(s.registrationMAC(issuer(r), payload))
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": id, "client_name": c.Name, "redirect_uris": c.Redirects, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
}

func (s *Server) validateAuthorization(q url.Values, origin string) (registration, bool) {
	var c registration
	payload, tag, ok := strings.Cut(q.Get("client_id"), ".")
	signature, err := raw64.DecodeString(tag)
	if !ok || err != nil || !hmac.Equal(signature, s.registrationMAC(origin, payload)) {
		return c, false
	}
	b, err := raw64.DecodeString(payload)
	if err != nil || json.Unmarshal(b, &c) != nil || len(c.Redirects) != 1 {
		return c, false
	}
	challenge, err := raw64.DecodeString(q.Get("code_challenge"))
	return c, err == nil && len(challenge) == 32 && q.Get("code_challenge_method") == "S256" && q.Get("response_type") == "code" && q.Get("redirect_uri") == c.Redirects[0] && q.Get("resource") == origin+"/mcp" && (q.Get("scope") == "" || q.Get("scope") == diagnosticsScope)
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.validateAuthorization(q, issuer(r))
	if !ok {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	q.Set("client_name", c.Name)
	// The destination is always the panel root. Client input is encoded inside its fragment.
	w.Header().Set("Location", "/#mcp?"+q.Encode())
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) oauthApprove(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAvailable(w, r) {
		return
	}
	var body struct {
		Query string `json:"query"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	q, err := url.ParseQuery(body.Query)
	c, ok := s.validateAuthorization(q, issuer(r))
	if err != nil || !ok || q.Get("client_name") != c.Name {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	p, _ := auth.PrincipalFrom(r.Context())
	code := newSecret()
	err = s.Eng.Store.ApproveMCP(r.Context(), store.MCPGrant{ID: uuid.NewString(), Name: c.Name, ApprovedBy: p.Username}, issuer(r), q.Get("client_id"), c.Redirects[0], q.Get("code_challenge"), digest(code))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	u, _ := url.Parse(c.Redirects[0])
	v := u.Query()
	v.Set("code", code)
	v.Set("iss", issuer(r))
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	writeJSON(w, http.StatusOK, map[string]string{"redirect": u.String()})
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if r.ParseForm() != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	o := issuer(r)
	access, refresh := newSecret(), newSecret()
	err := sql.ErrNoRows
	if f.Get("resource") == o+"/mcp" || f.Get("resource") == "" {
		switch f.Get("grant_type") {
		case "authorization_code":
			if verifierPattern.MatchString(f.Get("code_verifier")) {
				err = s.Eng.Store.ExchangeMCP(r.Context(), o, f.Get("client_id"), digest(f.Get("code")), f.Get("redirect_uri"), digest(f.Get("code_verifier")), digest(access), digest(refresh))
			}
		case "refresh_token":
			err = s.Eng.Store.RefreshMCP(r.Context(), o, f.Get("client_id"), digest(f.Get("refresh_token")), digest(access), digest(refresh))
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 600, "scope": diagnosticsScope})
}

func (s *Server) oauthResource(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && len(token) == 43 {
		err := s.Eng.Store.UseMCP(r.Context(), issuer(r), digest(token))
		if err == nil {
			s.mcpTransport.ServeHTTP(w, r)
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			writeInternalError(w, err)
			return
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+issuer(r)+resourceMeta+`", scope="`+diagnosticsScope+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (s *Server) oauthGrants(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAvailable(w, r) {
		return
	}
	g, err := s.Eng.Store.MCPGrants(r.Context(), issuer(r))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}
func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAvailable(w, r) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid grant", http.StatusBadRequest)
		return
	}
	if err = s.Eng.Store.RevokeMCP(r.Context(), issuer(r), id.String()); err != nil {
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(204)
}
