// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

const acmeChallengeURLPrefix = "/.well-known/acme-challenge/"

// acmeInternalListenAddr returns the loopback address for the HTTP-01 helper that
// HAProxy's bk_acme backend proxies to. Empty means disabled.
//
// configured is the acme_internal_http setting, which is also what the renderer
// writes into the bk_acme backend. The environment variable stays supported so
// that an appliance can switch the helper off without a database round-trip, and
// so that installs that already move it keep working:
//
//	EASY_WAF_ACME_INTERNAL_HTTP unset or empty → the setting (or its default)
//	"0", "off", "false"                        → disabled
//	anything else                              → used as-is
//
// Using it to *move* the helper is the case worth warning about: the backend
// follows the setting, so the two then point at different ports and HTTP-01
// fails with nothing in the logs but a failing health check. acmeInternalAddrs
// reports that mismatch to the caller.
func acmeInternalListenAddr(configured string) string {
	v := strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_ACME_INTERNAL_HTTP"), "\r", ""))
	if v == "0" || strings.EqualFold(v, "off") || strings.EqualFold(v, "false") {
		return ""
	}
	if v == "" {
		return config.ACMEInternalHTTPOrDefault(configured)
	}
	return v
}

// acmeInternalAddrs returns the address the helper will listen on and the
// address the generated HAProxy backend will dial. They differ only when
// EASY_WAF_ACME_INTERNAL_HTTP overrides a different acme_internal_http setting.
func acmeInternalAddrs(configured string) (listen, backend string) {
	return acmeInternalListenAddr(configured), config.ACMEInternalHTTPOrDefault(configured)
}

// acmeChallengeHandler serves Lego HTTP-01 files from webroot (same layout as
// github.com/go-acme/lego/v4/providers/http/webroot): webroot/.well-known/acme-challenge/<token>.
func acmeChallengeHandler(webroot string) http.Handler {
	base := filepath.Clean(webroot)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean(r.URL.Path)
		if p != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(p, acmeChallengeURLPrefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(p, acmeChallengeURLPrefix)
		if token == "" || strings.Contains(token, "/") {
			http.NotFound(w, r)
			return
		}
		full := filepath.Join(base, ".well-known", "acme-challenge", token)
		rel, err := filepath.Rel(base, full)
		if err != nil || strings.HasPrefix(rel, "..") {
			http.NotFound(w, r)
			return
		}
		fi, err := os.Stat(full)
		if err != nil || fi.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, full)
	})
}

func acmeWebrootPath(stateDir, configured string) (string, error) {
	wr := strings.TrimSpace(configured)
	if wr == "" {
		wr = filepath.Join(stateDir, "acme", "webroot")
	}
	wr = filepath.Clean(wr)
	if wr == "" || wr == "." {
		return "", errors.New("invalid ACME webroot")
	}
	return wr, nil
}
