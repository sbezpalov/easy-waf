// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/metrics"
)

const (
	diagnosticOK            = "ok"
	diagnosticFailed        = "failed"
	diagnosticUnknown       = "unknown"
	diagnosticNotApplicable = "not_applicable"

	applicationDiagnosticsTimeout = 5 * time.Second
	maxCertificateMaterialBytes   = 2 << 20
)

var (
	errCertificateMaterialMissing = errors.New("certificate material is missing")
	errCertificateMaterialInvalid = errors.New("certificate material is invalid")
)

// ApplicationDiagnosticStep is one independently sourced fact in the
// application availability chain. Code is stable for clients; Summary and
// Evidence are operator-facing English text and never contain raw errors.
type ApplicationDiagnosticStep struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Status   string   `json:"status"`
	Code     string   `json:"code"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
}

// ApplicationDiagnosticsResponse is the read-only response for
// GET /api/v1/applications/{id}/diagnostics.
type ApplicationDiagnosticsResponse struct {
	ApplicationID string                      `json:"application_id"`
	CheckedAt     time.Time                   `json:"checked_at"`
	Status        string                      `json:"status"`
	Summary       string                      `json:"summary"`
	Steps         []ApplicationDiagnosticStep `json:"steps"`
}

type applicationDiagnosticFacts struct {
	App config.Application
	Now time.Time

	DNSAddresses []string
	DNSError     error

	Certificate          *config.Certificate
	CertificateError     error
	CertificateLeaf      *x509.Certificate
	CertificateLeafError error

	EdgeStatus config.EdgeStatus
	EdgeError  error
	LiveSHA    string
	LiveError  error

	HAProxyReport *metrics.HAProxyReport
	HAProxyError  error
}

type diagnosticDNSResult struct {
	addresses []string
	err       error
}

type diagnosticHAProxyResult struct {
	report *metrics.HAProxyReport
	err    error
}

func (s *Server) getApplicationDiagnostics(w http.ResponseWriter, r *http.Request) {
	app, ok := s.loadApplication(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	now := time.Now().UTC()
	facts := applicationDiagnosticFacts{App: app, Now: now}

	facts.EdgeStatus, facts.EdgeError = s.Eng.Store.GetEdgeStatus(r.Context())
	if facts.EdgeError != nil {
		log.Printf("api: application diagnostics %q edge state: %v", app.ID, facts.EdgeError)
	}
	facts.LiveSHA, facts.LiveError = s.Eng.LiveHAProxySHA256()

	if config.ListenModeRequiresCertificate(app.ListenMode) {
		facts.Certificate, facts.CertificateError = s.findCertificate(r.Context(), app.CertificateID)
		if facts.CertificateError != nil && !errors.Is(facts.CertificateError, sql.ErrNoRows) {
			log.Printf("api: application diagnostics %q certificate: %v", app.ID, facts.CertificateError)
		}
		if facts.Certificate != nil {
			facts.CertificateLeaf, facts.CertificateLeafError = readCertificateLeaf(certificateMaterialPath(facts.Certificate))
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), applicationDiagnosticsTimeout)
	defer cancel()
	dnsResult := make(chan diagnosticDNSResult, 1)
	statsResult := make(chan diagnosticHAProxyResult, 1)
	go func() {
		addresses, err := net.DefaultResolver.LookupHost(ctx, app.PublicHost)
		dnsResult <- diagnosticDNSResult{addresses: addresses, err: err}
	}()
	go func() {
		path := metrics.StatsSocketPath(s.Eng.Settings(), s.Eng.StateDir)
		report, err := s.haproxyStats().FetchContext(ctx, path)
		statsResult <- diagnosticHAProxyResult{report: report, err: err}
	}()

	dns := <-dnsResult
	stats := <-statsResult
	if r.Context().Err() != nil {
		return
	}
	facts.DNSAddresses, facts.DNSError = dns.addresses, dns.err
	facts.HAProxyReport, facts.HAProxyError = stats.report, stats.err
	writeJSON(w, http.StatusOK, buildApplicationDiagnostics(facts))
}

func buildApplicationDiagnostics(facts applicationDiagnosticFacts) ApplicationDiagnosticsResponse {
	app := facts.App
	config.NormalizeListenMode(&app)
	steps := make([]ApplicationDiagnosticStep, 0, 6)
	steps = append(steps, publicationDiagnosticStep(app))
	steps = append(steps, dnsDiagnosticStep(facts.DNSAddresses, facts.DNSError))
	steps = append(steps, tlsDiagnosticStep(app, facts.Certificate, facts.CertificateError, facts.CertificateLeaf, facts.CertificateLeafError, facts.Now))
	route := appliedRouteDiagnosticStep(app, facts.EdgeStatus, facts.EdgeError, facts.LiveSHA, facts.LiveError)
	steps = append(steps, route)
	runtime, backend := runtimeDiagnosticSteps(app, route, facts.HAProxyReport, facts.HAProxyError)
	steps = append(steps, runtime, backend)

	status := diagnosticOK
	summary := "All applicable checks passed."
	for _, step := range steps {
		if step.Status == diagnosticFailed {
			status = diagnosticFailed
			summary = step.Summary
			break
		}
	}
	if status == diagnosticOK {
		for _, step := range steps {
			if step.Status == diagnosticUnknown {
				status = diagnosticUnknown
				summary = "Some checks could not be verified."
				break
			}
		}
	}
	return ApplicationDiagnosticsResponse{
		ApplicationID: app.ID,
		CheckedAt:     facts.Now.UTC(),
		Status:        status,
		Summary:       summary,
		Steps:         steps,
	}
}

func publicationDiagnosticStep(app config.Application) ApplicationDiagnosticStep {
	step := diagnosticStep("publication", "Publication", diagnosticOK, "publication_enabled", "Application publication is enabled.")
	if !app.Enabled {
		step.Status, step.Code, step.Summary = diagnosticFailed, "application_disabled", "Application publication is disabled."
		return step
	}
	if app.Maintenance {
		step.Status, step.Code, step.Summary = diagnosticFailed, "maintenance_enabled", "Maintenance mode intentionally returns HTTP 503."
		return step
	}
	return step
}

func dnsDiagnosticStep(addresses []string, err error) ApplicationDiagnosticStep {
	addresses = uniqueSortedStrings(addresses, 8)
	if len(addresses) > 0 {
		step := diagnosticStep("dns", "DNS", diagnosticOK, "hostname_resolved", "Public hostname resolves from the appliance.")
		step.Evidence = []string{"Addresses: " + strings.Join(addresses, ", ")}
		return step
	}
	if err == nil {
		return diagnosticStep("dns", "DNS", diagnosticFailed, "no_dns_addresses", "Public hostname returned no addresses.")
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return diagnosticStep("dns", "DNS", diagnosticFailed, "hostname_not_found", "Public hostname was not found in DNS.")
	}
	return diagnosticStep("dns", "DNS", diagnosticUnknown, "dns_lookup_unavailable", "DNS lookup could not be verified from the appliance.")
}

func tlsDiagnosticStep(app config.Application, certificate *config.Certificate, certificateErr error, leaf *x509.Certificate, leafErr error, now time.Time) ApplicationDiagnosticStep {
	if !config.ListenModeRequiresCertificate(app.ListenMode) {
		return diagnosticStep("tls", "TLS", diagnosticNotApplicable, "tls_not_required", "TLS is not required for this HTTP-only publication.")
	}
	if strings.TrimSpace(app.CertificateID) == "" {
		return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_not_assigned", "No certificate is assigned to this HTTPS publication.")
	}
	if certificateErr != nil {
		if errors.Is(certificateErr, sql.ErrNoRows) {
			return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_not_found", "The assigned certificate no longer exists.")
		}
		return diagnosticStep("tls", "TLS", diagnosticUnknown, "certificate_metadata_unavailable", "Certificate metadata could not be verified.")
	}
	if certificate == nil {
		return diagnosticStep("tls", "TLS", diagnosticUnknown, "certificate_metadata_unavailable", "Certificate metadata could not be verified.")
	}
	if leafErr != nil {
		switch {
		case errors.Is(leafErr, errCertificateMaterialMissing), errors.Is(leafErr, os.ErrNotExist):
			code, summary := "certificate_material_missing", "Certificate material is missing on the appliance."
			status := strings.ToLower(strings.TrimSpace(certificate.ACMEStatus))
			switch status {
			case "pending", "issuing":
				code, summary = "certificate_pending", "Certificate issuance is still pending."
			case "failed":
				code, summary = "certificate_issuance_failed", "Certificate issuance or renewal failed and no usable material was found."
			}
			return diagnosticStep("tls", "TLS", diagnosticFailed, code, summary)
		case errors.Is(leafErr, errCertificateMaterialInvalid):
			return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_material_invalid", "Certificate material cannot be parsed.")
		default:
			return diagnosticStep("tls", "TLS", diagnosticUnknown, "certificate_material_unavailable", "Certificate material could not be read by the API.")
		}
	}
	if leaf == nil {
		return diagnosticStep("tls", "TLS", diagnosticUnknown, "certificate_material_unavailable", "Certificate material could not be verified.")
	}
	if now.Before(leaf.NotBefore) {
		return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_not_yet_valid", "Certificate is not valid yet.")
	}
	if !now.Before(leaf.NotAfter) {
		return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_expired", "Certificate has expired.")
	}
	if err := leaf.VerifyHostname(app.PublicHost); err != nil {
		return diagnosticStep("tls", "TLS", diagnosticFailed, "certificate_hostname_mismatch", "Certificate does not cover the public hostname.")
	}
	step := diagnosticStep("tls", "TLS", diagnosticOK, "certificate_valid", "Certificate material is valid for the public hostname.")
	step.Evidence = []string{"Expires: " + leaf.NotAfter.UTC().Format(time.RFC3339)}
	if acme := strings.TrimSpace(certificate.ACMEStatus); acme != "" {
		step.Evidence = append(step.Evidence, "Issuance status: "+acme)
	}
	return step
}

func appliedRouteDiagnosticStep(app config.Application, edge config.EdgeStatus, edgeErr error, liveSHA string, liveErr error) ApplicationDiagnosticStep {
	if !app.Enabled {
		return diagnosticStep("applied_route", "Applied route", diagnosticNotApplicable, "application_disabled", "A disabled application is not rendered to HAProxy.")
	}
	if edgeErr != nil {
		return diagnosticStep("applied_route", "Applied route", diagnosticUnknown, "edge_state_unavailable", "Saved and applied edge generations could not be compared.")
	}
	if edge.Pending == nil || edge.AppliedGeneration == nil {
		return diagnosticStep("applied_route", "Applied route", diagnosticUnknown, "applied_generation_unknown", "The applied edge generation is not known.")
	}
	if *edge.Pending || *edge.AppliedGeneration != edge.SavedGeneration {
		step := diagnosticStep("applied_route", "Applied route", diagnosticFailed, "edge_changes_pending", "Saved edge changes are not the applied generation.")
		step.Evidence = []string{fmt.Sprintf("Saved generation: %d", edge.SavedGeneration), fmt.Sprintf("Applied generation: %d", *edge.AppliedGeneration)}
		return step
	}
	if liveErr != nil || strings.TrimSpace(liveSHA) == "" {
		return diagnosticStep("applied_route", "Applied route", diagnosticUnknown, "live_artifact_unavailable", "The managed live HAProxy artifact could not be verified.")
	}
	if edge.LastApply == nil || edge.LastApply.Outcome != config.EdgeApplyOutcomeSuccess || strings.TrimSpace(edge.LastApply.RevisionSHA) == "" {
		return diagnosticStep("applied_route", "Applied route", diagnosticUnknown, "live_artifact_provenance_unknown", "The live artifact has no matching successful apply record.")
	}
	if !strings.EqualFold(strings.TrimSpace(edge.LastApply.RevisionSHA), strings.TrimSpace(liveSHA)) {
		return diagnosticStep("applied_route", "Applied route", diagnosticFailed, "live_artifact_mismatch", "The live HAProxy artifact differs from the recorded applied revision.")
	}
	step := diagnosticStep("applied_route", "Applied route", diagnosticOK, "edge_generation_applied", "This saved application generation is present in the verified live artifact.")
	step.Evidence = []string{fmt.Sprintf("Generation: %d", edge.SavedGeneration), "Revision: " + shortDiagnosticSHA(liveSHA)}
	return step
}

func runtimeDiagnosticSteps(app config.Application, route ApplicationDiagnosticStep, report *metrics.HAProxyReport, reportErr error) (ApplicationDiagnosticStep, ApplicationDiagnosticStep) {
	if !app.Enabled {
		return diagnosticStep("runtime", "HAProxy runtime", diagnosticNotApplicable, "application_disabled", "A disabled application has no HAProxy backend."),
			diagnosticStep("backend", "Backend", diagnosticNotApplicable, "application_disabled", "Backend health is not applicable while the application is disabled.")
	}
	if route.Status != diagnosticOK {
		return diagnosticStep("runtime", "HAProxy runtime", diagnosticUnknown, "applied_route_unverified", "Runtime data cannot be attributed to the current saved route."),
			diagnosticStep("backend", "Backend", diagnosticUnknown, "applied_route_unverified", "Backend health cannot be attributed to the current saved route.")
	}
	if reportErr != nil || report == nil || strings.TrimSpace(report.Error) != "" {
		return diagnosticStep("runtime", "HAProxy runtime", diagnosticUnknown, "haproxy_stats_unavailable", "HAProxy runtime statistics are unavailable."),
			diagnosticStep("backend", "Backend", diagnosticUnknown, "haproxy_stats_unavailable", "Backend health is unknown because HAProxy statistics are unavailable.")
	}
	backendName := haproxy.ApplicationBackendName(app.PublicHost)
	var backend *metrics.BackendStat
	for i := range report.Backends {
		if report.Backends[i].Name == backendName {
			backend = &report.Backends[i]
			break
		}
	}
	if backend == nil {
		return diagnosticStep("runtime", "HAProxy runtime", diagnosticFailed, "backend_not_loaded", "The application backend is absent from HAProxy runtime statistics."),
			diagnosticStep("backend", "Backend", diagnosticUnknown, "backend_not_loaded", "Backend health cannot be read because the HAProxy backend is absent.")
	}
	runtime := diagnosticStep("runtime", "HAProxy runtime", diagnosticOK, "backend_loaded", "HAProxy reports the application backend.")
	runtime.Evidence = []string{"Backend: " + backendName}
	if !report.CollectedAt.IsZero() {
		runtime.Evidence = append(runtime.Evidence, "Collected: "+report.CollectedAt.UTC().Format(time.RFC3339))
	}
	health := strings.ToLower(strings.TrimSpace(backend.Health))
	if health == "" {
		health = strings.ToLower(strings.TrimSpace(backend.Status))
	}
	serverEvidence := backendServerEvidence(backend.Servers)
	switch health {
	case "healthy", "up", "open":
		step := diagnosticStep("backend", "Backend", diagnosticOK, "backend_healthy", "HAProxy health checks report the backend available.")
		step.Evidence = serverEvidence
		return runtime, step
	case "degraded":
		step := diagnosticStep("backend", "Backend", diagnosticFailed, "backend_degraded", "HAProxy reports a degraded backend pool.")
		step.Evidence = serverEvidence
		return runtime, step
	case "down", "maint", "nolb", "stopped":
		step := diagnosticStep("backend", "Backend", diagnosticFailed, "backend_down", "HAProxy health checks report the backend unavailable.")
		step.Evidence = serverEvidence
		return runtime, step
	default:
		step := diagnosticStep("backend", "Backend", diagnosticUnknown, "backend_health_unknown", "HAProxy did not provide a recognized backend health state.")
		step.Evidence = serverEvidence
		return runtime, step
	}
}

func diagnosticStep(id, label, status, code, summary string) ApplicationDiagnosticStep {
	return ApplicationDiagnosticStep{ID: id, Label: label, Status: status, Code: code, Summary: summary, Evidence: []string{}}
}

func backendServerEvidence(servers []metrics.ServerStat) []string {
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		out = append(out, fmt.Sprintf("%s: %s", server.Name, strings.TrimSpace(server.Status)))
	}
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("%d more servers", len(out)-8))
	}
	return out
}

func uniqueSortedStrings(values []string, limit int) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func shortDiagnosticSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func certificateMaterialPath(certificate *config.Certificate) string {
	if certificate == nil {
		return ""
	}
	for _, candidate := range []string{certificate.BundlePath, certificate.FullchainPath, certificate.PEMCrtPath} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return ""
}

func readCertificateLeaf(path string) (*x509.Certificate, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errCertificateMaterialMissing
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	material, err := io.ReadAll(io.LimitReader(file, maxCertificateMaterialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(material) > maxCertificateMaterialBytes {
		return nil, fmt.Errorf("%w: material exceeds size limit", errCertificateMaterialInvalid)
	}
	for len(material) > 0 {
		block, rest := pem.Decode(material)
		if block == nil {
			break
		}
		material = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errCertificateMaterialInvalid, err)
		}
		return leaf, nil
	}
	return nil, errCertificateMaterialInvalid
}
