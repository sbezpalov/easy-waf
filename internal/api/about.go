// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

type aboutComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source"`
}

type aboutResponse struct {
	Version    string           `json:"version"`
	GoVersion  string           `json:"go_version"`
	Platform   string           `json:"platform"`
	Revision   string           `json:"revision,omitempty"`
	SourceTime string           `json:"source_time,omitempty"`
	Modified   bool             `json:"modified,omitempty"`
	Components []aboutComponent `json:"components"`
	License    string           `json:"license"`
	Terms      string           `json:"license_text"`
	Notice     string           `json:"notice"`
}

var aboutPackages = []struct{ key, name string }{
	{"easy-waf", "Easy Home WAF (API, ACME worker, host broker and CLI)"},
	{"haproxy", "HAProxy"},
	{"crowdsec", "CrowdSec"},
	{"crowdsec-haproxy-spoa-bouncer", "CrowdSec HAProxy bouncer"},
	{"fail2ban", "Fail2Ban"},
	{"nftables", "nftables"},
}

var aboutModules = []struct{ path, name string }{
	{"github.com/jackc/pgx/v5", "pgx (PostgreSQL driver)"},
	{"github.com/oschwald/maxminddb-golang", "MaxMind DB reader"},
	{"github.com/prometheus/client_golang", "Prometheus client"},
}

const aboutCheckTimeout = 2 * time.Second

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	components := installedAboutComponents(r.Context())
	db := aboutComponent{Name: "PostgreSQL", Source: "Connected database"}
	if s.Eng.Store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), aboutCheckTimeout)
		version, err := s.Eng.Store.ServerVersion(ctx)
		cancel()
		if err == nil {
			db.Version = version
		}
	}
	components = append(components, db)

	var revision string
	var sourceTime string
	var modified bool
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.time":
				sourceTime = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		components = append(components, linkedAboutComponents(info.Deps)...)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, aboutResponse{
		Version: easywaf.Version(), GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Revision: revision, SourceTime: sourceTime, Modified: modified, Components: components,
		License: "Apache-2.0", Terms: easywaf.LicenseText(), Notice: easywaf.NoticeText(),
	})
}

func linkedAboutComponents(deps []*debug.Module) []aboutComponent {
	versions := make(map[string]string, len(deps))
	for _, dep := range deps {
		version := dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}
		if version != "(devel)" {
			versions[dep.Path] = version
		}
	}
	components := make([]aboutComponent, 0, len(aboutModules))
	for _, module := range aboutModules {
		components = append(components, aboutComponent{
			Name: module.name, Version: versions[module.path], Source: "Linked into the management API",
		})
	}
	return components
}

func installedAboutComponents(ctx context.Context) []aboutComponent {
	var versions map[string]string
	if runtime.GOOS == "linux" {
		args := make([]string, 0, 2+len(aboutPackages))
		args = append(args, "-W", "-f=${Package}\t${db:Status-Status}\t${Version}\n")
		for _, pkg := range aboutPackages {
			args = append(args, pkg.key)
		}
		// dpkg-query may report a missing optional package and still print
		// complete rows for the packages it found.
		out, _ := runner.Run(ctx, aboutCheckTimeout, "/usr/bin/dpkg-query", args...)
		versions = parseInstalledAboutVersions(string(out))
	}
	components := make([]aboutComponent, 0, len(aboutPackages))
	for _, pkg := range aboutPackages {
		components = append(components, aboutComponent{Name: pkg.name, Version: versions[pkg.key], Source: "Installed package"})
	}
	return components
}

func parseInstalledAboutVersions(out string) map[string]string {
	versions := make(map[string]string)
	// Only newline-terminated records represent complete command output.
	for {
		line, rest, complete := strings.Cut(out, "\n")
		if !complete {
			break
		}
		out = rest
		fields := strings.Split(line, "\t")
		if len(fields) == 3 && fields[1] == "installed" {
			versions[fields[0]] = fields[2]
		}
	}
	return versions
}
