// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func testMMDBBytes(t *testing.T, ip, iso string) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		IPVersion:    4,
		RecordSize:   24,
		Inserter:     inserter.ReplaceWith,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert(n, mmdbtype.Map{
		"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)},
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testServer(t *testing.T, provider string) *Server {
	t.Helper()
	dir := t.TempDir()
	s := &Server{Eng: engine.New(dir, nil, config.GlobalSettings{GeoIPProvider: provider})}
	if provider == "maxmind" {
		// The runtime resolves its reader from settings, so an appliance already
		// configured for MaxMind points at the managed file.
		cfg := s.Eng.Settings()
		cfg.GeoIPMMDBPath = filepath.Join(s.geoipDir(), "GeoLite2-Country.mmdb")
		s.Eng.SetSettings(cfg)
	}
	return s
}

func TestInstallGeoIPDatabase_activatesWhenProviderIsMaxMind(t *testing.T) {
	s := testServer(t, "maxmind")
	resp, status, err := s.installGeoIPDatabase(bytes.NewReader(testMMDBBytes(t, "8.8.8.8", "US")))
	if err != nil || status != http.StatusOK {
		t.Fatalf("install failed: status=%d err=%v", status, err)
	}
	if !resp.Reloaded {
		t.Fatal("database was installed but the runtime was not reloaded")
	}
	want := filepath.Join(s.geoipDir(), "GeoLite2-Country.mmdb")
	if resp.Path != want {
		t.Fatalf("installed at %q, want %q", resp.Path, want)
	}
	// The runtime must now answer from the uploaded database.
	got, _, err := s.Eng.GeoIP().Lookup(context.Background(), s.Eng.Settings(), "8.8.8.8")
	if err != nil || got != "US" {
		t.Fatalf("live lookup after upload: %q, %v", got, err)
	}
}

// Uploading a database must not switch an ipinfo appliance over by itself.
func TestInstallGeoIPDatabase_doesNotHijackIpinfoProvider(t *testing.T) {
	s := testServer(t, "ipinfo")
	resp, status, err := s.installGeoIPDatabase(bytes.NewReader(testMMDBBytes(t, "8.8.8.8", "US")))
	if err != nil || status != http.StatusOK {
		t.Fatalf("install failed: status=%d err=%v", status, err)
	}
	if resp.Reloaded {
		t.Fatal("runtime was switched to the uploaded database without the operator changing provider")
	}
	if resp.ActivateHint == "" {
		t.Fatal("no hint telling the operator how to activate the upload")
	}
	if _, err := os.Stat(resp.Path); err != nil {
		t.Fatalf("database not stored: %v", err)
	}
}

// A bad upload must be rejected and must not disturb the database in use.
func TestInstallGeoIPDatabase_keepsLiveDatabaseOnRejection(t *testing.T) {
	s := testServer(t, "maxmind")
	good := testMMDBBytes(t, "8.8.8.8", "US")
	if _, _, err := s.installGeoIPDatabase(bytes.NewReader(good)); err != nil {
		t.Fatalf("first install: %v", err)
	}
	live := filepath.Join(s.geoipDir(), "GeoLite2-Country.mmdb")

	_, status, err := s.installGeoIPDatabase(strings.NewReader("not a database at all"))
	if err == nil {
		t.Fatal("garbage upload accepted")
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	current, readErr := os.ReadFile(live)
	if readErr != nil || !bytes.Equal(current, good) {
		t.Fatal("rejected upload modified the live database")
	}
	if got, _, err := s.Eng.GeoIP().Lookup(context.Background(), s.Eng.Settings(), "8.8.8.8"); err != nil || got != "US" {
		t.Fatalf("runtime broken after a rejected upload: %q, %v", got, err)
	}
	// No leftovers in the GeoIP directory.
	entries, _ := os.ReadDir(s.geoipDir())
	for _, e := range entries {
		if e.Name() != "GeoLite2-Country.mmdb" {
			t.Fatalf("unexpected file left behind: %s", e.Name())
		}
	}
}

// Storing a database at a path the settings do not point at must not claim the
// runtime was switched: geoip.ProviderForRuntime would re-resolve from settings
// on the next lookup and quietly undo it.
func TestInstallGeoIPDatabase_noFalseActivationOnPathMismatch(t *testing.T) {
	s := testServer(t, "maxmind")
	cfg := s.Eng.Settings()
	cfg.GeoIPMMDBPath = "/var/lib/easy-waf/geoip/SomeOther.mmdb"
	s.Eng.SetSettings(cfg)

	resp, status, err := s.installGeoIPDatabase(bytes.NewReader(testMMDBBytes(t, "8.8.8.8", "US")))
	if err != nil || status != http.StatusOK {
		t.Fatalf("install failed: status=%d err=%v", status, err)
	}
	if resp.Reloaded {
		t.Fatal("claimed activation while geoip_mmdb_path points elsewhere")
	}
	if !strings.Contains(resp.ActivateHint, resp.Path) {
		t.Fatalf("hint does not name the installed path: %q", resp.ActivateHint)
	}
}
