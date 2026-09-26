// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
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
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	path := strings.TrimSpace(body.MmdbPath)
	if path == "" {
		path = strings.TrimSpace(s.Eng.Settings().GeoIPMMDBPath)
	}
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geoip_mmdb_path is empty"})
		return
	}
	if err := s.Eng.GeoIP().ReloadMaxMindDB(path); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.Eng.GeoIP().Cache.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
