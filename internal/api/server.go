package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/ipwl"
	"github.com/easy-waf/easy-waf/internal/mgmttls"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// Server exposes REST API for the UI and automation.
type Server struct {
	Eng       *engine.Engine
	JWTSecret []byte
	// MgmtTLS optional: when set, PUT /settings/management-tls replaces cert on disk and in-memory (HTTPS listener).
	MgmtTLS         *mgmttls.Manager
	MgmtTLSCertPath string
	MgmtTLSKeyPath  string
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// True-Client-IP → X-Real-IP → X-Forwarded-For (left); trust only behind a trusted reverse proxy (see docs/SECURITY.md).
	r.Use(middleware.RealIP)
	r.Use(s.managementACL)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", s.handleLogin)
		r.Group(func(r chi.Router) {
			r.Use(auth.Session(s.Eng.Store, s.JWTSecret))
			r.Get("/auth/me", s.handleAuthMe)
			r.Post("/auth/change-password", s.handleChangePassword)
		})
		r.Group(func(r chi.Router) {
			r.Use(auth.Session(s.Eng.Store, s.JWTSecret))
			r.Use(auth.PasswordChangeGate)
			r.Get("/status", s.handleStatus)
			r.Get("/profiles", s.handleProfiles)
			r.Get("/applications", s.listApps)
			r.Post("/applications", s.upsertApp)
			r.Delete("/applications/{id}", s.deleteApp)
			r.Get("/certificates", s.listCerts)
			r.Post("/certificates", s.upsertCert)
			r.Post("/apply", s.apply)
			r.Get("/integrations/crowdsec", s.crowdsecStatus)
			r.Get("/integrations/crowdsec/decisions", s.crowdsecDecisions)
			r.Get("/settings", s.getSettings)
			r.Put("/settings", s.putSettings)
			r.Patch("/settings", s.patchSettings)
			r.Put("/settings/management-tls", s.putManagementTLS)

			r.Get("/ipbl/local", s.listIPBLLocal)
			r.Post("/ipbl/local", s.upsertIPBLLocal)
			r.Delete("/ipbl/local/{id}", s.deleteIPBLLocal)
			r.Get("/ipbl/sources", s.listIPBLSources)
			r.Post("/ipbl/sources", s.upsertIPBLSource)
			r.Post("/ipbl/sync", s.syncIPBL)

			r.Get("/ipwl/local", s.listIPWLLocal)
			r.Post("/ipwl/local", s.upsertIPWLLocal)
			r.Delete("/ipwl/local/{id}", s.deleteIPWLLocal)

			r.Post("/certificates/{id}/request-issue", s.requestCertIssue)
		})
	})
	return r
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"state_dir": s.Eng.StateDir,
		"version":   os.Getenv("EASY_WAF_VERSION"),
	})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	out := map[string]profiles.Profile{}
	for k, v := range profiles.All() {
		out[string(k)] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.Eng.Store.ListApplications(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, apps)
}

func (s *Server) upsertApp(w http.ResponseWriter, r *http.Request) {
	var a config.Application
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := profiles.Resolve(a.Profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "app.upsert", map[string]string{"id": a.ID, "host": a.PublicHost})
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteApplication(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "app.delete", map[string]string{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	c, err := s.Eng.Store.ListCertificates(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) upsertCert(w http.ResponseWriter, r *http.Request) {
	var c config.Certificate
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertCertificate(r.Context(), &c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "cert.upsert", map[string]string{"id": c.ID, "domain": c.PrimaryDomain})
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.Eng.Apply(r.Context(), body.Label); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

func (s *Server) crowdsecStatus(w http.ResponseWriter, r *http.Request) {
	c := crowdsec.Client{BaseURL: s.Eng.Settings.CrowdSecLAPIURL, APIKey: s.Eng.Settings.CrowdSecLAPIKey}
	writeJSON(w, http.StatusOK, c.Ping(r.Context()))
}

func (s *Server) crowdsecDecisions(w http.ResponseWriter, r *http.Request) {
	c := crowdsec.Client{BaseURL: s.Eng.Settings.CrowdSecLAPIURL, APIKey: s.Eng.Settings.CrowdSecLAPIKey}
	raw, err := c.DecisionsSample(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Eng.Settings)
}

func (s *Server) putManagementTLS(w http.ResponseWriter, r *http.Request) {
	if s.MgmtTLS == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "HTTPS management is disabled (EASY_WAF_MANAGEMENT_HTTPS=0)"})
		return
	}
	var body struct {
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.CertificatePEM) == "" || strings.TrimSpace(body.PrivateKeyPEM) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate_pem and private_key_pem required"})
		return
	}
	if err := s.MgmtTLS.Store(s.MgmtTLSCertPath, s.MgmtTLSKeyPath, []byte(body.CertificatePEM), []byte(body.PrivateKeyPEM)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "mgmt.tls.replaced", map[string]string{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) patchSettings(w http.ResponseWriter, r *http.Request) {
	s.mergeAndPersistSettings(w, r, "settings.patch")
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	s.mergeAndPersistSettings(w, r, "settings.put")
}

// mergeAndPersistSettings reads the body as a JSON object and merges it over current settings.
// Omitted keys keep existing values (PATCH semantics). PUT uses the same merge so partial bodies
// do not zero paths or durations; send only the fields you want to change, or use GET → edit → PUT.
func (s *Server) mergeAndPersistSettings(w http.ResponseWriter, r *http.Request, auditAction string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	gs, err := config.ApplySettingsJSONPatch(s.Eng.Settings, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if gs.CrowdSecLAPIKey == "" {
		gs.CrowdSecLAPIKey = s.Eng.Settings.CrowdSecLAPIKey
	}
	if gs.ACMEEmail == "" {
		gs.ACMEEmail = s.Eng.Settings.ACMEEmail
	}
	if gs.ManagementAllowedCIDRs == nil {
		gs.ManagementAllowedCIDRs = s.Eng.Settings.ManagementAllowedCIDRs
	}
	if err := validateManagementCIDRs(gs.ManagementAllowedCIDRs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Eng.Settings = gs
	if err := s.Eng.SaveSettings(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), auditAction, map[string]string{})
	writeJSON(w, http.StatusOK, s.Eng.Settings)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) listIPBLLocal(w http.ResponseWriter, r *http.Request) {
	list, err := s.Eng.Store.ListIPBLLocal(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) upsertIPBLLocal(w http.ResponseWriter, r *http.Request) {
	var e config.IPBLLocalEntry
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertIPBLLocal(r.Context(), &e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "ipbl.local.upsert", map[string]string{"id": e.ID, "cidr": e.CIDR})
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteIPBLLocal(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteIPBLLocal(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listIPBLSources(w http.ResponseWriter, r *http.Request) {
	list, err := s.Eng.Store.ListIPBLExternalSources(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) upsertIPBLSource(w http.ResponseWriter, r *http.Request) {
	var e config.IPBLExternalSource
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertIPBLExternalSource(r.Context(), &e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) syncIPBL(w http.ResponseWriter, r *http.Request) {
	res, err := ipbl.SyncAndWrite(r.Context(), s.Eng.Store, s.Eng.Settings, s.Eng.StateDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := ipwl.WriteLocalMap(r.Context(), s.Eng.Store, ipwl.MapPath(s.Eng.Settings, s.Eng.StateDir)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "ipbl.sync", map[string]any{"total": res.TotalLines})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listIPWLLocal(w http.ResponseWriter, r *http.Request) {
	list, err := s.Eng.Store.ListIPWLLocal(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) upsertIPWLLocal(w http.ResponseWriter, r *http.Request) {
	var e config.IPWLLocalEntry
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e.CIDR = strings.TrimSpace(e.CIDR)
	if e.CIDR == "" {
		http.Error(w, "cidr required", http.StatusBadRequest)
		return
	}
	if err := validateIPOrCIDR(e.CIDR); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Eng.Store.UpsertIPWLLocal(r.Context(), &e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "ipwl.local.upsert", map[string]string{"id": e.ID, "cidr": e.CIDR})
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteIPWLLocal(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteIPWLLocal(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Eng.Store.AppendAudit(r.Context(), "ipwl.local.delete", map[string]string{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func validateIPOrCIDR(s string) error {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid ip or cidr")
	}
	return nil
}

func (s *Server) requestCertIssue(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Mode                  string `json:"mode"`
		DNSProvider           string `json:"dns_provider"`
		DNSCredentialsEnvFile string `json:"dns_credentials_env_file"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	certs, err := s.Eng.Store.ListCertificates(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found *config.Certificate
	for i := range certs {
		if certs[i].ID == id {
			found = &certs[i]
			break
		}
	}
	if found == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	found.ACMEStatus = "pending"
	if body.Mode != "" {
		found.Mode = body.Mode
	} else {
		found.Mode = "http-01"
	}
	if body.DNSProvider != "" {
		found.DNSProvider = body.DNSProvider
	}
	if body.DNSCredentialsEnvFile != "" {
		found.DNSCredentialsEnvFile = body.DNSCredentialsEnvFile
	}
	if err := s.Eng.Store.UpsertCertificate(r.Context(), found); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, found)
}
