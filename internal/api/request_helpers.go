// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// maxJSONObjectBytes caps bodies read whole for a JSON merge (settings,
// security PATCH).
const maxJSONObjectBytes = 1 << 20

// decodeJSONRequest requires one complete value followed only by whitespace.
// Initial EOF is preserved for endpoints with optional bodies. Existing body
// readers retain their route-specific byte limits.
func decodeJSONRequest(r *http.Request, value any) error {
	if r.Body == nil {
		return io.EOF
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("request body must contain a single JSON value")
	}
	return nil
}

// readJSONBody reads a request body of at most maxJSONObjectBytes. A larger
// body is a 413; it used to be cut off silently and reported as a confusing
// JSON syntax error. It reports false when it has written the response.
func readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONObjectBytes))
	if err == nil {
		return body, true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit), http.StatusRequestEntityTooLarge)
		return nil, false
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
	return nil, false
}

// findCertificate returns the stored certificate id, or sql.ErrNoRows.
func (s *Server) findCertificate(ctx context.Context, id string) (*config.Certificate, error) {
	certs, err := s.Eng.Store.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	for i := range certs {
		if certs[i].ID == id {
			return &certs[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// dnsProviders are the DNS-01 providers easy-waf-acmed can drive
// (internal/acme newDNSProvider); empty means the default.
var dnsProviders = map[string]struct{}{"": {}, "cloudflare": {}, "cloudns": {}, "route53": {}, "webhook": {}}

// validateCertificateDNS checks the DNS-01 fields before they are stored.
//
// easy-waf-acmed opens dns_credentials_env_file and loads its KEY=value lines
// into its own environment, so the path must stay where operators keep such
// files — /etc/easy-waf or the state directory's secrets — rather than name
// any file acmed can read. An unknown provider used to surface only as a
// failed issuance.
//
// Only a dns-01 certificate uses them, so others are not held to the rules: a
// value stored earlier must not block an http-01 issuance. The provider is
// expected normalized (normalizeDNSProvider).
func validateCertificateDNS(stateDir string, c config.Certificate) error {
	if c.Mode != "dns-01" {
		return nil
	}
	if _, ok := dnsProviders[c.DNSProvider]; !ok {
		return fmt.Errorf("dns_provider %q is not supported (use cloudflare, cloudns, route53 or webhook)", c.DNSProvider)
	}
	p := c.DNSCredentialsEnvFile
	if p == "" {
		return nil
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("dns_credentials_env_file contains control characters")
	}
	if err := config.ValidateAbsoluteConfigFilePath("dns_credentials_env_file", p, false); err != nil {
		return err
	}
	for _, dir := range []string{"/etc/easy-waf", pathpkg.Join(stateDir, "secrets")} {
		if config.TargetPathWithin(p, dir) {
			return nil
		}
	}
	return fmt.Errorf("dns_credentials_env_file must be under /etc/easy-waf/ or %s/", pathpkg.Join(stateDir, "secrets"))
}

// normalizeDNSProvider stores the provider name the way acmed matches it.
func normalizeDNSProvider(c *config.Certificate) {
	c.DNSProvider = strings.ToLower(strings.TrimSpace(c.DNSProvider))
}

// writeDeleteError answers a failed delete: 404 for an unknown id, else 500.
func writeDeleteError(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		writeClientError(w, http.StatusNotFound, "not found", nil)
		return
	}
	writeInternalError(w, err)
}
