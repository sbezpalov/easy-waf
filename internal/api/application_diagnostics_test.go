// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/metrics"
)

func TestBuildApplicationDiagnosticsHealthy(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sha := strings.Repeat("a", 64)
	applied, pending := int64(9), false
	app := config.Application{
		ID:            "app-1",
		PublicHost:    "home.example.com",
		CertificateID: "cert-1",
		ListenMode:    "https_only",
		Enabled:       true,
	}
	response := buildApplicationDiagnostics(applicationDiagnosticFacts{
		App:          app,
		Now:          now,
		DNSAddresses: []string{"203.0.113.8", "203.0.113.8"},
		Certificate:  &config.Certificate{ID: "cert-1", ACMEStatus: "ready"},
		CertificateLeaf: &x509.Certificate{
			DNSNames:  []string{"home.example.com"},
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(60 * 24 * time.Hour),
		},
		EdgeStatus: config.EdgeStatus{
			SavedGeneration:   9,
			AppliedGeneration: &applied,
			Pending:           &pending,
			LastApply:         &config.EdgeLastApply{Outcome: config.EdgeApplyOutcomeSuccess, RevisionSHA: sha},
		},
		LiveSHA: sha,
		HAProxyReport: &metrics.HAProxyReport{
			CollectedAt: now,
			Backends: []metrics.BackendStat{{
				Name:    haproxy.ApplicationBackendName(app.PublicHost),
				Status:  "UP",
				Health:  "healthy",
				Servers: []metrics.ServerStat{{Name: "s1", Status: "UP"}},
			}},
		},
	})
	if response.Status != diagnosticOK || response.Summary != "All applicable checks passed." {
		t.Fatalf("unexpected response: %+v", response)
	}
	if len(response.Steps) != 6 {
		t.Fatalf("got %d steps, want 6", len(response.Steps))
	}
	for _, id := range []string{"publication", "dns", "tls", "applied_route", "runtime", "backend"} {
		step := diagnosticStepByID(t, response, id)
		if step.Status != diagnosticOK {
			t.Errorf("%s status = %s (%s)", id, step.Status, step.Code)
		}
	}
	if got := diagnosticStepByID(t, response, "dns").Evidence; len(got) != 1 || strings.Count(got[0], "203.0.113.8") != 1 {
		t.Fatalf("DNS evidence is not deduplicated: %v", got)
	}
}

func TestBuildApplicationDiagnosticsKeepsFailureAndUnknownDistinct(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sha := strings.Repeat("b", 64)
	applied, pending := int64(4), false
	app := config.Application{ID: "app-2", PublicHost: "cam.example.com", ListenMode: "http_only", Enabled: true}
	base := applicationDiagnosticFacts{
		App:          app,
		Now:          now,
		DNSAddresses: []string{"198.51.100.9"},
		EdgeStatus: config.EdgeStatus{
			SavedGeneration:   4,
			AppliedGeneration: &applied,
			Pending:           &pending,
			LastApply:         &config.EdgeLastApply{Outcome: config.EdgeApplyOutcomeSuccess, RevisionSHA: sha},
		},
		LiveSHA: sha,
	}

	t.Run("backend down is a failure", func(t *testing.T) {
		facts := base
		facts.HAProxyReport = &metrics.HAProxyReport{Backends: []metrics.BackendStat{{
			Name: haproxy.ApplicationBackendName(app.PublicHost), Health: "down", Status: "DOWN",
			Servers: []metrics.ServerStat{{Name: "s1", Status: "DOWN"}},
		}}}
		response := buildApplicationDiagnostics(facts)
		if response.Status != diagnosticFailed {
			t.Fatalf("overall status = %s, want failed", response.Status)
		}
		backend := diagnosticStepByID(t, response, "backend")
		if backend.Status != diagnosticFailed || backend.Code != "backend_down" {
			t.Fatalf("unexpected backend step: %+v", backend)
		}
		if tls := diagnosticStepByID(t, response, "tls"); tls.Status != diagnosticNotApplicable {
			t.Fatalf("HTTP-only TLS status = %s", tls.Status)
		}
	})

	t.Run("unavailable observations stay unknown", func(t *testing.T) {
		facts := base
		facts.DNSAddresses = nil
		facts.DNSError = errors.New("private resolver detail")
		facts.HAProxyError = errors.New("private socket detail")
		response := buildApplicationDiagnostics(facts)
		if response.Status != diagnosticUnknown {
			t.Fatalf("overall status = %s, want unknown", response.Status)
		}
		for _, id := range []string{"dns", "runtime", "backend"} {
			step := diagnosticStepByID(t, response, id)
			if step.Status != diagnosticUnknown {
				t.Errorf("%s = %+v", id, step)
			}
			if strings.Contains(step.Summary, "private") {
				t.Errorf("%s leaked raw error: %+v", id, step)
			}
		}
	})
}

func TestBuildApplicationDiagnosticsExplainsPendingAndIntentionalOutage(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	applied, pending := int64(7), true
	app := config.Application{
		ID: "app-3", PublicHost: "nvr.example.com", ListenMode: "http_only", Enabled: true, Maintenance: true,
	}
	response := buildApplicationDiagnostics(applicationDiagnosticFacts{
		App: app, Now: now, DNSAddresses: []string{"192.0.2.4"},
		EdgeStatus: config.EdgeStatus{SavedGeneration: 8, AppliedGeneration: &applied, Pending: &pending},
	})
	publication := diagnosticStepByID(t, response, "publication")
	if publication.Code != "maintenance_enabled" || response.Summary != publication.Summary {
		t.Fatalf("maintenance is not the primary explanation: response=%+v step=%+v", response, publication)
	}
	route := diagnosticStepByID(t, response, "applied_route")
	if route.Status != diagnosticFailed || route.Code != "edge_changes_pending" {
		t.Fatalf("pending route: %+v", route)
	}
	if runtime := diagnosticStepByID(t, response, "runtime"); runtime.Status != diagnosticUnknown || runtime.Code != "applied_route_unverified" {
		t.Fatalf("runtime claimed current saved state: %+v", runtime)
	}
}

func TestReadCertificateLeaf(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture.example.com"},
		DNSNames:     []string{"fixture.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := readCertificateLeaf(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("fixture.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := readCertificateLeaf(""); !errors.Is(err, errCertificateMaterialMissing) {
		t.Fatalf("empty path error = %v", err)
	}
}

func diagnosticStepByID(t *testing.T, response ApplicationDiagnosticsResponse, id string) ApplicationDiagnosticStep {
	t.Helper()
	for _, step := range response.Steps {
		if step.ID == id {
			return step
		}
	}
	t.Fatalf("missing diagnostic step %q", id)
	return ApplicationDiagnosticStep{}
}
