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
)

const acmeChallengeURLPrefix = "/.well-known/acme-challenge/"

// acmeInternalListenAddr returns the loopback address for the HTTP-01 helper that
// HAProxy's bk_acme backend proxies to. Empty means disabled.
//
// Env EASY_WAF_ACME_INTERNAL_HTTP: unset or empty → "127.0.0.1:8089";
// "0", "off", "false" (case-insensitive) → disabled; otherwise used as-is (e.g. "127.0.0.1:9090").
func acmeInternalListenAddr() string {
	v := strings.TrimSpace(strings.ReplaceAll(os.Getenv("EASY_WAF_ACME_INTERNAL_HTTP"), "\r", ""))
	if v == "0" || strings.EqualFold(v, "off") || strings.EqualFold(v, "false") {
		return ""
	}
	if v == "" {
		return "127.0.0.1:8089"
	}
	return v
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
