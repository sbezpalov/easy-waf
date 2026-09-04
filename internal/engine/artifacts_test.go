// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
)

func writeArtifactTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readArtifactTestFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func newArtifactTestEngine(t *testing.T) *Engine {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	return &Engine{
		StateDir: stateDir,
		Settings: config.DefaultSettings(stateDir),
	}
}

func TestArtifactTransactionRollbackRestoresCompleteSet(t *testing.T) {
	e := newArtifactTestEngine(t)
	_, cfgPath, crtListPath := haproxy.Paths(e.StateDir)
	ipblPath := e.Settings.IPBlacklistMapPath
	oldGeoPath := filepath.Join(e.StateDir, "haproxy", "geoip_app_old.map")
	newGeoPath := filepath.Join(e.StateDir, "haproxy", "geoip_app_new.map")

	writeArtifactTestFile(t, cfgPath, "config-v1")
	writeArtifactTestFile(t, crtListPath, "crt-list-v1")
	writeArtifactTestFile(t, ipblPath, "192.0.2.1")
	writeArtifactTestFile(t, oldGeoPath, "198.51.100.0/24")

	tx, err := e.beginArtifactTransaction()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.remove() })

	writeArtifactTestFile(t, cfgPath, "config-v2")
	writeArtifactTestFile(t, crtListPath, "crt-list-v2")
	writeArtifactTestFile(t, ipblPath, "203.0.113.1")
	if err := os.Remove(oldGeoPath); err != nil {
		t.Fatal(err)
	}
	writeArtifactTestFile(t, newGeoPath, "203.0.113.0/24")

	if err := tx.rollback(); err != nil {
		t.Fatal(err)
	}
	if got := readArtifactTestFile(t, cfgPath); got != "config-v1" {
		t.Fatalf("config after rollback = %q", got)
	}
	if got := readArtifactTestFile(t, crtListPath); got != "crt-list-v1" {
		t.Fatalf("crt-list after rollback = %q", got)
	}
	if got := readArtifactTestFile(t, ipblPath); got != "192.0.2.1" {
		t.Fatalf("IPBL map after rollback = %q", got)
	}
	if got := readArtifactTestFile(t, oldGeoPath); got != "198.51.100.0/24" {
		t.Fatalf("old per-app GeoIP map after rollback = %q", got)
	}
	if _, err := os.Stat(newGeoPath); !os.IsNotExist(err) {
		t.Fatalf("new per-app GeoIP map still exists after rollback: %v", err)
	}
}

func TestRevisionArtifactManifestRestoresSet(t *testing.T) {
	e := newArtifactTestEngine(t)
	_, cfgPath, crtListPath := haproxy.Paths(e.StateDir)
	geoPath := filepath.Join(e.StateDir, "haproxy", "geoip_app_one.map")

	writeArtifactTestFile(t, cfgPath, "config-v1")
	writeArtifactTestFile(t, crtListPath, "crt-list-v1")
	writeArtifactTestFile(t, geoPath, "192.0.2.0/24")
	cfgSHA, err := sha256HexFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := e.createRevisionSnapshot(cfgSHA, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.remove() })

	writeArtifactTestFile(t, cfgPath, "config-v2")
	writeArtifactTestFile(t, crtListPath, "crt-list-v2")
	writeArtifactTestFile(t, geoPath, "203.0.113.0/24")

	current, err := e.managedArtifactPaths(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := restoreArtifactManifest(snapshot.ManifestPath, current, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ConfigSHA256 != cfgSHA {
		t.Fatalf("manifest config SHA = %q, want %q", manifest.ConfigSHA256, cfgSHA)
	}
	if got := readArtifactTestFile(t, cfgPath); got != "config-v1" {
		t.Fatalf("config after manifest restore = %q", got)
	}
	if got := readArtifactTestFile(t, crtListPath); got != "crt-list-v1" {
		t.Fatalf("crt-list after manifest restore = %q", got)
	}
	if got := readArtifactTestFile(t, geoPath); got != "192.0.2.0/24" {
		t.Fatalf("GeoIP map after manifest restore = %q", got)
	}
}

func TestArtifactManifestRejectsCorruptBackupBeforeRestore(t *testing.T) {
	e := newArtifactTestEngine(t)
	_, cfgPath, _ := haproxy.Paths(e.StateDir)
	writeArtifactTestFile(t, cfgPath, "config-v1")
	cfgSHA, err := sha256HexFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.createRevisionSnapshot(cfgSHA, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.remove() })

	configFile, ok := manifestFileForPath(snapshot.Manifest, cfgPath)
	if !ok {
		t.Fatal("snapshot does not contain config")
	}
	backupPath := filepath.Join(snapshot.Dir, filepath.FromSlash(configFile.BackupPath))
	writeArtifactTestFile(t, backupPath, "corrupt")
	writeArtifactTestFile(t, cfgPath, "live-must-survive")

	current, err := e.managedArtifactPaths(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreArtifactManifest(snapshot.ManifestPath, current, cfgPath); err == nil ||
		!strings.Contains(err.Error(), "checksum") && !strings.Contains(err.Error(), "size/type") {
		t.Fatalf("restore error = %v, want checksum/size rejection", err)
	}
	if got := readArtifactTestFile(t, cfgPath); got != "live-must-survive" {
		t.Fatalf("live config changed before manifest validation: %q", got)
	}
}

func TestArtifactTransactionIncludesConfiguredExternalMap(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	externalMap := filepath.Join(root, "external", "ip-blacklist.map")
	e := &Engine{
		StateDir: stateDir,
		Settings: config.DefaultSettings(stateDir),
	}
	e.Settings.IPBlacklistMapPath = externalMap

	_, cfgPath, _ := haproxy.Paths(stateDir)
	writeArtifactTestFile(t, cfgPath, "config-v1")
	writeArtifactTestFile(t, externalMap, "192.0.2.10")
	writeArtifactTestFile(t, filepath.Join(stateDir, "certs", "c1", "bundle.pem"), "private-key-material")

	tx, err := e.beginArtifactTransaction()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.remove() })
	if !tx.snapshot.hasFile(externalMap) {
		t.Fatal("configured external map is missing from transaction snapshot")
	}
	for _, file := range tx.snapshot.Manifest.ManagedFiles {
		if strings.Contains(filepath.ToSlash(file.Path), "/certs/") {
			t.Fatalf("certificate material must not be copied into revisions: %s", file.Path)
		}
	}

	writeArtifactTestFile(t, externalMap, "203.0.113.10")
	if err := tx.rollback(); err != nil {
		t.Fatal(err)
	}
	if got := readArtifactTestFile(t, externalMap); got != "192.0.2.10" {
		t.Fatalf("external map after rollback = %q", got)
	}
}
