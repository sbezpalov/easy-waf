// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/geoip"
)

// geoipDatabaseUploadPath is exempt from the global request body limit — the
// handler below applies its own, larger cap (see limitRequestBody).
const geoipDatabaseUploadPath = "/api/v1/geoip/database"

// geoipUploadMu serializes database installs. Two concurrent uploads would race
// on the same destination file and could leave the runtime pointing at the
// loser's database.
var geoipUploadMu sync.Mutex

// geoipDir is the only directory an uploaded database may land in. The
// destination is derived here and never taken from the request.
func (s *Server) geoipDir() string {
	return filepath.Join(s.Eng.StateDir, "geoip")
}

type geoipUploadResponse struct {
	geoip.MMDBInfo
	// Reloaded is true when the live reader now serves this file. It stays false
	// when the database was stored but geoip_provider / geoip_mmdb_path still
	// point somewhere else — the operator has to save those settings first.
	Reloaded     bool   `json:"reloaded"`
	ActivateHint string `json:"activate_hint,omitempty"`
}

// geoipUploadDatabase accepts a GeoLite2 database and installs it.
//
// The body is the raw file: either a .mmdb or the .tar.gz MaxMind publishes.
// The format is detected from the content, so no client-supplied file name is
// trusted, and nothing replaces the live database until the uploaded file has
// been opened as a MaxMind database and answered a real lookup.
func (s *Server) geoipUploadDatabase(w http.ResponseWriter, r *http.Request) {
	// The route is exempt from the global 4 MiB limit; apply the large cap here.
	r.Body = http.MaxBytesReader(w, r.Body, geoip.MaxMMDBBytes+1)

	geoipUploadMu.Lock()
	defer geoipUploadMu.Unlock()

	resp, status, err := s.installGeoIPDatabase(r.Body)
	if err != nil {
		out := map[string]string{"error": err.Error()}
		if resp.Path != "" {
			out["mmdb_path"] = resp.Path
		}
		writeJSON(w, status, out)
		return
	}
	info := resp.MMDBInfo

	_ = s.Eng.Store.AppendAudit(r.Context(), "geoip_database_uploaded", map[string]any{
		"mmdb_path":     info.Path,
		"database_type": info.DatabaseType,
		"build_epoch":   info.BuildEpoch.Format(time.RFC3339),
		"size_bytes":    info.SizeBytes,
		"node_count":    info.NodeCount,
		"reloaded":      resp.Reloaded,
	})

	writeJSON(w, http.StatusOK, resp)
}

// installGeoIPDatabase does the work behind the upload endpoint: extract,
// validate, install, and reload the runtime when MaxMind is the active provider.
// It touches neither the request nor the store, so the whole path is testable
// without an HTTP server or a database.
func (s *Server) installGeoIPDatabase(body io.Reader) (geoipUploadResponse, int, error) {
	var resp geoipUploadResponse

	dir := s.geoipDir()
	tmpPath, err := geoip.ExtractMMDB(body, dir)
	if err != nil {
		return resp, http.StatusBadRequest, err
	}

	info, err := geoip.InstallMMDB(tmpPath, dir)
	if err != nil {
		_ = os.Remove(tmpPath)
		return resp, http.StatusBadRequest, err
	}
	resp.MMDBInfo = info

	// The runtime resolves its provider from settings (geoip.ProviderForRuntime
	// keys the cached reader on geoip_mmdb_path), so reloading only sticks when
	// the configured path is the file we just installed. Anything else would
	// report an activation that the next lookup silently undoes — and uploading
	// a database must not switch an ipinfo appliance over by itself either.
	provider := strings.EqualFold(strings.TrimSpace(s.Eng.Settings.GeoIPProvider), "maxmind")
	configured := strings.TrimSpace(s.Eng.Settings.GeoIPMMDBPath) == info.Path
	if !provider || !configured {
		resp.ActivateHint = "set geoip_provider=maxmind and geoip_mmdb_path=" + info.Path + ", then save settings"
		return resp, http.StatusOK, nil
	}

	if s.Eng.GeoIP == nil {
		s.Eng.GeoIP = geoip.NewRuntime(time.Duration(s.Eng.Settings.GeoIPCacheTTL))
	}
	if err := s.Eng.GeoIP.ReloadMaxMindDB(info.Path); err != nil {
		return resp, http.StatusBadGateway, fmt.Errorf("database installed but reload failed: %w", err)
	}
	s.Eng.GeoIP.Cache.Clear()
	resp.Reloaded = true
	return resp, http.StatusOK, nil
}
