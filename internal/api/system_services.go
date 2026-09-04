// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// coreSystemdUnits are inspected with `systemctl show` (fallback `is-active`) for the dashboard / ops view.
var coreSystemdUnits = []struct {
	ID    string `json:"id"`
	Unit  string `json:"unit"`
	Label string `json:"label"`
}{
	{"easy_waf_api", "easy-waf-api.service", "Control plane + UI"},
	{"easy_waf_acmed", "easy-waf-acmed.service", "ACME worker"},
	{"haproxy", "haproxy.service", "Edge TLS / routing"},
	{"crowdsec", "crowdsec.service", "CrowdSec engine + LAPI"},
	{"crowdsec_spoa", "crowdsec-spoa-bouncer.service", "HAProxy SPOA bouncer"},
	{"nftables", "nftables.service", "Host firewall (nftables)"},
	{"fail2ban", "fail2ban.service", "Fail2ban"},
	{"postgresql", "postgresql.service", "PostgreSQL (local default unit name)"},
}

// systemctlBins are tried in order (minimal PATH under systemd sometimes omits /usr/bin).
var systemctlBins = []string{"/usr/bin/systemctl", "/bin/systemctl", "systemctl"}

// systemdUnitActiveState returns systemd ActiveState (active, inactive, failed, activating, …)
// or "unknown" if systemctl is missing / D-Bus is unreachable / unit name not loaded.
func systemdUnitActiveState(ctx context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Prefer `systemctl show`: exit status is usually 0 even for inactive units (unlike `is-active`, which uses 3/4).
	for _, bin := range systemctlBins {
		if out, err := exec.CommandContext(ctx, bin, "show", "-p", "ActiveState", "--value", unit).Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
		// `is-active` prints a state line even when exit code is non-zero (e.g. inactive → exit 3).
		out, err := exec.CommandContext(ctx, bin, "is-active", unit).Output()
		s := strings.TrimSpace(string(out))
		if s != "" {
			return s
		}
		_ = err
	}
	return "unknown"
}

func (s *Server) listSystemServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type row struct {
		ID          string `json:"id"`
		Unit        string `json:"unit"`
		Label       string `json:"label"`
		ActiveState string `json:"active_state"`
	}
	out := make([]row, 0, len(coreSystemdUnits))
	for _, u := range coreSystemdUnits {
		out = append(out, row{
			ID:          u.ID,
			Unit:        u.Unit,
			Label:       u.Label,
			ActiveState: systemdUnitActiveState(ctx, u.Unit),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}
