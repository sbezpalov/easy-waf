// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

func readAboutForTest(t *testing.T, s *Server) aboutResponse {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleAbout(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/about", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("about status %d headers %v", w.Code, w.Header())
	}
	var about aboutResponse
	if err := json.Unmarshal(w.Body.Bytes(), &about); err != nil {
		t.Fatal(err)
	}
	return about
}

func TestAboutReportsShippedVersionAndTerms(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	info := readAboutForTest(t, &Server{Eng: &engine.Engine{}})
	if info.Version != strings.TrimSpace(read("VERSION")) || info.GoVersion != runtime.Version() ||
		info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("incorrect runtime identity: %q, %q, %q", info.Version, info.GoVersion, info.Platform)
	}
	if info.License != "Apache-2.0" || info.Terms != read("LICENSE") || info.Notice != read("NOTICE") {
		t.Fatal("expected the build's complete license and attribution files")
	}
	if len(info.Components) != len(aboutPackages)+1 || info.Components[len(info.Components)-1] != (aboutComponent{Name: "PostgreSQL", Source: "Connected database"}) {
		t.Fatalf("expected package inventory with an unavailable database: %+v", info.Components)
	}
	if runtime.GOOS == "linux" {
		out, err := runner.Run(t.Context(), aboutCheckTimeout, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}", "haproxy")
		installed, want := strings.CutPrefix(string(out), "installed\t")
		if err == nil && want && info.Components[1].Version != installed {
			t.Fatalf("HAProxy installed version: got %q, want %q", info.Components[1].Version, installed)
		}
	}
}

func TestAboutReportsConnectedDatabaseVersion(t *testing.T) {
	s := applyFailingServer(t)
	info := readAboutForTest(t, s)
	got := info.Components[len(info.Components)-1]
	want, err := s.Eng.Store.ServerVersion(t.Context())
	if err != nil || want == "" || got.Version != want || got.Name != "PostgreSQL" {
		t.Fatalf("database version: got %+v, want %q, error %v", got, want, err)
	}
}

func TestParseInstalledAboutVersions(t *testing.T) {
	versions := parseInstalledAboutVersions("haproxy\tinstalled\t2.8.30-0ubuntu0.24.04.2\n" +
		"fail2ban\tconfig-files\t1.0.2-3\n" + "nftables\tinstalled\t1.0.")
	if len(versions) != 1 || versions["haproxy"] != "2.8.30-0ubuntu0.24.04.2" {
		t.Fatalf("unexpected installed versions: %v", versions)
	}
}
