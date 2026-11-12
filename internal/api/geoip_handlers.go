// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

type geoipProviderRow struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	MMDBPath  string `json:"mmdb_path,omitempty"`
}

func (s *Server) geoipListProviders(w http.ResponseWriter, _ *http.Request) {
	path := strings.TrimSpace(s.Eng.Settings().GeoIPMMDBPath)
	ok := path != ""
	if ok {
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			ok = false
		}
	}
	writeJSON(w, http.StatusOK, []geoipProviderRow{
		{Name: "ipinfo", Available: true},
		{Name: "maxmind", Available: ok, MMDBPath: path},
	})
}

func (s *Server) geoipReload(w http.ResponseWriter, r *http.Request) {
	if strings.ToLower(strings.TrimSpace(s.Eng.Settings().GeoIPProvider)) != "maxmind" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geoip_provider is not maxmind"})
		return
	}
	var body struct {
		MmdbPath string `json:"mmdb_path"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// An empty body reloads the configured path; a malformed one is an error
	// rather than a silent reload of something the caller did not ask for.
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	path := strings.TrimSpace(body.MmdbPath)
	if path == "" {
		path = strings.TrimSpace(s.Eng.Settings().GeoIPMMDBPath)
	}
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geoip_mmdb_path is empty"})
		return
	}
	if err := s.allowlistedGeoIPMMDBPath(path); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Eng.GeoIP().ReloadMaxMindDB(path); err != nil {
		writeClientError(w, http.StatusBadGateway, "internal error", err)
		return
	}
	s.Eng.GeoIP().Cache.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// allowlistedGeoIPMMDBPath restricts probe/reload opens to the appliance GeoIP
// data directory and /etc/easy-waf (same render-safe rules as other config paths).
func (s *Server) allowlistedGeoIPMMDBPath(path string) error {
	path = strings.TrimSpace(path)
	if err := config.ValidateConfigFilePath("mmdb_path", path, false); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("mmdb_path must be an absolute path")
	}
	clean := filepath.Clean(path)
	for _, dir := range []string{s.geoipDir(), "/etc/easy-waf"} {
		root := filepath.Clean(dir)
		prefix := root + string(filepath.Separator)
		if strings.HasPrefix(clean, prefix) {
			return nil
		}
	}
	return fmt.Errorf("mmdb_path must be under %s/ or /etc/easy-waf/", s.geoipDir())
}
