// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/mgmttls"
)

func TestValidateCertificateDNS(t *testing.T) {
	const state = "/var/lib/easy-waf"
	cases := []struct {
		name     string
		provider string
		env      string
		ok       bool
	}{
		{"defaults", "", "", true},
		{"etc file", "cloudflare", "/etc/easy-waf/dns/cf.env", true},
		{"state secrets", "route53", "/var/lib/easy-waf/secrets/dns/r53.env", true},
		{"provider case", "CloudNS", "", true},
		{"unknown provider", "godaddy", "", false},
		{"relative", "", "dns/cf.env", false},
		{"traversal", "", "/etc/easy-waf/../shadow", false},
		{"outside", "", "/etc/shadow", false},
		{"prefix lookalike", "", "/etc/easy-waf-other/x.env", false},
		{"state dir outside secrets", "", "/var/lib/easy-waf/haproxy/haproxy.cfg", false},
		{"control char", "", "/etc/easy-waf/a\nb.env", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCertificateDNS(state, config.Certificate{DNSProvider: tc.provider, DNSCredentialsEnvFile: tc.env})
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestReadJSONBodyTooLargeIs413(t *testing.T) {
	big := strings.NewReader(`{"x":"` + strings.Repeat("a", maxJSONObjectBytes) + `"}`)
	rec := httptest.NewRecorder()
	if _, ok := readJSONBody(rec, httptest.NewRequest(http.MethodPatch, "/api/v1/settings", big)); ok {
		t.Fatal("oversized body accepted")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRequestIssueRejectsMalformedBody(t *testing.T) {
	s := &Server{}
	req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/v1/certificates/x/request-issue", strings.NewReader(`{"mode":`)), "id", "x")
	rec := httptest.NewRecorder()
	s.requestCertIssue(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPutManagementTLSStatus(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := mgmttls.EnsureSelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		certPath string
		cert     []byte
		want     int
	}{
		{"invalid pair", filepath.Join(dir, "a.crt"), []byte("not a certificate"), http.StatusBadRequest},
		{"write fails", filepath.Join(blocker, "a.crt"), certPEM, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{MgmtTLS: &mgmttls.Manager{}, MgmtTLSCertPath: tc.certPath, MgmtTLSKeyPath: filepath.Join(dir, "a.key")}
			body, _ := json.Marshal(map[string]string{"certificate_pem": string(tc.cert), "private_key_pem": string(keyPEM)})
			rec := httptest.NewRecorder()
			s.putManagementTLS(rec, httptest.NewRequest(http.MethodPut, "/api/v1/settings/management-tls", strings.NewReader(string(body))))
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestStatsCollectorInitIsRaceFree is meaningful under -race.
func TestStatsCollectorInitIsRaceFree(t *testing.T) {
	dir := t.TempDir()
	s := &Server{Eng: engine.New(dir, nil, config.DefaultSettings(dir))}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.haproxyStats()
		}()
	}
	wg.Wait()
	if s.HAProxyMetrics == nil {
		t.Fatal("collector not created")
	}
}
