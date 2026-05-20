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
	{"crowdsec_spoa", "", "HAProxy SPOA bouncer"}, // unit resolved at runtime (see crowdsecSpoaUnit)
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

// systemdUnitLoadState returns LoadState from systemctl (loaded, not-found, …).
func systemdUnitLoadState(ctx context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, bin := range systemctlBins {
		if out, err := exec.CommandContext(ctx, bin, "show", "-p", "LoadState", "--value", unit).Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
	}
	return ""
}

// crowdsecSpoaUnit: Debian crowdsec-haproxy-spoa-bouncer package uses crowdsec-spoa-bouncer.service.
func crowdsecSpoaUnit(ctx context.Context) string {
	for _, u := range []string{
		"crowdsec-spoa-bouncer.service",
		"crowdsec-haproxy-spoa-bouncer.service",
	} {
		if systemdUnitLoadState(ctx, u) == "loaded" {
			return u
		}
	}
	return "crowdsec-spoa-bouncer.service"
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
		unit := u.Unit
		if u.ID == "crowdsec_spoa" {
			unit = crowdsecSpoaUnit(ctx)
		}
		out = append(out, row{
			ID:          u.ID,
			Unit:        unit,
			Label:       u.Label,
			ActiveState: systemdUnitActiveState(ctx, unit),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}
