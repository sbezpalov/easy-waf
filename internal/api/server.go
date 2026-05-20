package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/crowdsec"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/ipwl"
	"github.com/easy-waf/easy-waf/internal/metrics"
	"github.com/easy-waf/easy-waf/internal/mgmttls"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// Server exposes REST API for the UI and automation.
type Server struct {
	Eng       *engine.Engine
	JWTSecret []byte
	// LoginRL optional per-IP login rate limiter (nil skips limiting).
	LoginRL *LoginRateLimiter
	// MgmtTLS optional: when set, PUT /settings/management-tls replaces cert on disk and in-memory (HTTPS listener).
	MgmtTLS         *mgmttls.Manager
	MgmtTLSCertPath string
	MgmtTLSKeyPath  string
	HAProxyMetrics  *metrics.HAProxyCollector
	Prom            *metrics.PrometheusExporter
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// Forwarding headers apply only when the TCP peer is a trusted proxy (loopback by default); see docs/SECURITY.md.
	r.Use(TrustedRealIP(TrustedProxyCIDRs()))
	r.Use(s.managementACL)
	r.Use(RequireXHR)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", s.metricsHandler())

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", s.handleLogin)
		r.Group(func(r chi.Router) {
			r.Use(auth.Session(s.Eng.Store, s.JWTSecret))
			r.Use(attachAuditRequestMeta)
			r.Use(s.auditHTTPMutations)
			r.Get("/auth/me", s.handleAuthMe)
			r.Post("/auth/change-password", s.handleChangePassword)
			r.Group(func(r chi.Router) {
				r.Use(auth.PasswordChangeGate)
				r.Get("/status", s.handleStatus)
				r.Get("/system/services", s.listSystemServices)
				r.Get("/profiles", s.handleProfiles)
				r.Get("/security/modes", s.listSecurityModes)
				r.Get("/applications", s.listApps)
				r.Get("/applications/{id}", s.getApp)
				r.Post("/applications", s.upsertApp)
				r.Delete("/applications/{id}", s.deleteApp)
				r.Get("/applications/{id}/security", s.getAppSecurity)
				r.Put("/applications/{id}/security", s.putAppSecurity)
				r.Patch("/applications/{id}/security", s.patchAppSecurity)
				r.Post("/applications/{id}/security/mode", s.postAppSecurityMode)
				r.Get("/certificates/summary", s.listCertsSummary)
				r.Get("/certificates", s.listCerts)
				r.Post("/certificates", s.upsertCert)
				r.Delete("/certificates/{id}", s.deleteCert)
				r.Post("/apply", s.apply)
				r.Get("/revisions", s.listRevisions)
				r.Post("/revisions/{id}/rollback", s.postRevisionRollback)
				r.Get("/integrations/crowdsec", s.crowdsecStatus)
				r.Get("/integrations/crowdsec/decisions", s.crowdsecDecisions)
				r.Post("/integrations/crowdsec/decisions", s.crowdsecAddDecision)
				r.Delete("/integrations/crowdsec/decisions/{id}", s.crowdsecDeleteDecision)
				r.Get("/integrations/fail2ban", s.fail2banOverview)
				r.Get("/integrations/fail2ban/jails/{jail}", s.fail2banJailStatus)
				r.Post("/integrations/fail2ban/unban", s.fail2banUnban)
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

				r.Get("/security/blocked-ua", s.listBlockedUA)
				r.Post("/security/blocked-ua", s.addBlockedUA)
				r.Delete("/security/blocked-ua/{id}", s.deleteBlockedUA)

				r.Get("/geoip/lookup", s.geoipLookup)
				r.Get("/geoip/stats", s.geoipStats)
				r.Get("/geoip/providers", s.geoipListProviders)
				r.Post("/geoip/reload", s.geoipReload)

				r.Get("/stats/haproxy", s.handleStatsHAProxy)
				r.Get("/stats/summary", s.handleStatsSummary)

				r.Post("/certificates/{id}/request-issue", s.requestCertIssue)

				r.Get("/audit", s.listAudit)

				r.Post("/diagnostics/bundle", s.postDiagnosticsBundle)

				s.mountHostRoutes(r)
			})
		})
	})
	return r
}

func (s *Server) metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.Eng.Settings.PrometheusEnabled || s.Prom == nil {
			http.NotFound(w, r)
			return
		}
		s.Prom.Handler().ServeHTTP(w, r)
	})
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

func (s *Server) getApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := s.Eng.Store.GetApplication(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, a)
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
	config.NormalizeListenMode(&a)
	config.NormalizeApplicationSecurity(&a.Security)
	a.Security.Mode = string(profiles.DetectMode(a.Security))
	if config.ListenModeRequiresCertificate(a.ListenMode) && strings.TrimSpace(a.CertificateID) == "" {
		http.Error(w, "certificate_id is required for listen_mode "+a.ListenMode, http.StatusBadRequest)
		return
	}
	if err := validateAppHostnames(&a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var old config.Application
	haveOld := false
	if strings.TrimSpace(a.ID) != "" {
		prev, err := s.Eng.Store.GetApplication(r.Context(), a.ID)
		if err == nil {
			old = prev
			haveOld = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := s.Eng.Store.UpsertApplication(r.Context(), &a); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.maybeAutoApply(r.Context(), "api-application"); err != nil {
		http.Error(w, "application saved but edge apply failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if haveOld && old.ListenMode != a.ListenMode {
		detail := map[string]any{
			"app_id":   a.ID,
			"app_name": a.Name,
			"from":     old.ListenMode,
			"to":       a.ListenMode,
		}
		if a.ListenMode == "http_only" || old.ListenMode == "http_only" {
			detail["severity"] = "warn"
		}
		_ = s.Eng.Store.AppendAudit(r.Context(), "app_listen_mode_changed", detail)
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteApplication(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.maybeAutoApply(r.Context(), "api-application-delete"); err != nil {
		http.Error(w, "application deleted but edge apply failed: "+err.Error(), http.StatusBadGateway)
		return
	}
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

func (s *Server) listCertsSummary(w http.ResponseWriter, r *http.Request) {
	certs, err := s.Eng.Store.ListCertificates(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := BuildCertificateSummaryResponse(certs, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	n, err := s.Eng.Store.CountApplicationsByCertificateID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n > 0 {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": fmt.Sprintf("%d application(s) still reference this certificate; detach or delete them first", n),
		})
		return
	}
	if err := s.Eng.Store.DeleteCertificate(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.Eng.Apply(r.Context(), body.Label); err != nil {
		if s.Prom != nil {
			s.Prom.IncApplyError()
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.Prom != nil {
		s.Prom.IncApply()
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

// settingsAPIJSON is the JSON shape for settings API responses: never exposes CrowdSecLAPIKey (json:"-"),
// but adds crowdsec_lapi_key_set so the UI can show whether a key is stored.
type settingsAPIJSON struct {
	config.GlobalSettings
	CrowdSecLAPIKeySet bool `json:"crowdsec_lapi_key_set"`
}

func (s *Server) writeSettingsResponse(w http.ResponseWriter, code int, gs config.GlobalSettings) {
	writeJSON(w, code, settingsAPIJSON{
		GlobalSettings:     gs,
		CrowdSecLAPIKeySet: strings.TrimSpace(gs.CrowdSecLAPIKey) != "",
	})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	s.writeSettingsResponse(w, http.StatusOK, s.Eng.Settings)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) patchSettings(w http.ResponseWriter, r *http.Request) {
	s.mergeAndPersistSettings(w, r)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	s.mergeAndPersistSettings(w, r)
}

// mergeAndPersistSettings reads the body as a JSON object and merges it over current settings.
// Omitted keys keep existing values (PATCH semantics). PUT uses the same merge so partial bodies
// do not zero paths or durations; send only the fields you want to change, or use GET → edit → PUT.
func (s *Server) mergeAndPersistSettings(w http.ResponseWriter, r *http.Request) {
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
	if err := ValidateManagementCIDRs(gs.ManagementAllowedCIDRs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateGeoIPSettings(gs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Eng.Settings = gs
	if s.Eng.GeoIP != nil {
		s.Eng.GeoIP.InvalidateGeoProvider()
	}
	if err := s.Eng.SaveSettings(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeSettingsResponse(w, http.StatusOK, s.Eng.Settings)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// maybeAutoApply renders and reloads HAProxy after API mutations so the edge matches the database.
// Set EASY_WAF_NO_AUTO_APPLY=1 to skip (e.g. DB-only tooling); use POST /api/v1/apply manually instead.
func (s *Server) maybeAutoApply(ctx context.Context, label string) error {
	if strings.TrimSpace(os.Getenv("EASY_WAF_NO_AUTO_APPLY")) != "" {
		return nil
	}
	if err := s.Eng.Apply(ctx, label); err != nil {
		if s.Prom != nil {
			s.Prom.IncApplyError()
		}
		return err
	}
	if s.Prom != nil {
		s.Prom.IncApply()
	}
	return nil
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
	if err := s.Eng.WriteGeoIPEnforceMap(r.Context(), res.AllCIDRs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) geoipLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "ip query parameter required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if s.Eng.GeoIP == nil {
		s.Eng.GeoIP = geoip.NewRuntime(time.Duration(s.Eng.Settings.GeoIPCacheTTL))
	}
	if r.URL.Query().Get("nocache") == "1" && s.Eng.GeoIP.Cache != nil {
		s.Eng.GeoIP.Cache.Delete(ip)
	}
	g := s.Eng.Settings
	if probe := strings.TrimSpace(r.URL.Query().Get("probe_mmdb_path")); probe != "" {
		g.GeoIPMMDBPath = probe
		g.GeoIPProvider = "maxmind"
	}
	cc, cached, err := s.Eng.GeoIP.Lookup(r.Context(), g, ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": cc, "cached": cached})
}

func (s *Server) geoipStats(w http.ResponseWriter, r *http.Request) {
	if s.Eng.GeoIP == nil || s.Eng.GeoIP.Cache == nil {
		writeJSON(w, http.StatusOK, geoip.Stats{})
		return
	}
	writeJSON(w, http.StatusOK, s.Eng.GeoIP.Cache.Stats())
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
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteIPWLLocal(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteIPWLLocal(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listBlockedUA(w http.ResponseWriter, r *http.Request) {
	list, err := s.Eng.Store.ListBlockedUserAgents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) addBlockedUA(w http.ResponseWriter, r *http.Request) {
	var e config.BlockedUserAgent
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e.Pattern = strings.TrimSpace(e.Pattern)
	if e.Pattern == "" {
		http.Error(w, "pattern required", http.StatusBadRequest)
		return
	}
	e.ID = ""
	if err := s.Eng.Store.UpsertBlockedUserAgent(r.Context(), &e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteBlockedUA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Eng.Store.DeleteBlockedUserAgent(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateGeoIPSettings(gs config.GlobalSettings) error {
	p := strings.ToLower(strings.TrimSpace(gs.GeoIPDefaultPolicy))
	if p != "" && p != "allow" && p != "deny" {
		return fmt.Errorf("geoip_default_policy must be allow or deny")
	}
	pr := strings.ToLower(strings.TrimSpace(gs.GeoIPProvider))
	if pr != "" && pr != "ipinfo" && pr != "maxmind" {
		return fmt.Errorf("geoip_provider must be ipinfo or maxmind")
	}
	if gs.GeoIPEnabled && pr == "maxmind" && strings.TrimSpace(gs.GeoIPMMDBPath) == "" {
		return fmt.Errorf("geoip_mmdb_path is required when GeoIP is enabled and provider is maxmind")
	}
	return nil
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
