package api

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// coreSystemdUnits are inspected with `systemctl is-active` for the dashboard / ops view.
var coreSystemdUnits = []struct {
	ID    string `json:"id"`
	Unit  string `json:"unit"`
	Label string `json:"label"`
}{
	{"easy_waf_api", "easy-waf-api.service", "Control plane + UI"},
	{"easy_waf_acmed", "easy-waf-acmed.service", "ACME worker"},
	{"haproxy", "haproxy.service", "Edge TLS / routing"},
	{"crowdsec", "crowdsec.service", "CrowdSec engine + LAPI"},
	{"crowdsec_spoa", "crowdsec-haproxy-spoa-bouncer.service", "HAProxy SPOA bouncer"},
	{"firewalld", "firewalld.service", "Firewall (firewalld)"},
	{"fail2ban", "fail2ban.service", "Fail2ban"},
	{"postgresql", "postgresql.service", "PostgreSQL (local default unit name)"},
}

// systemdIsActive returns the first line from `systemctl is-active` (e.g. active, inactive, failed)
// or "unknown" if the command fails or times out.
func systemdIsActive(ctx context.Context, unit string) string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
	out, err := cmd.Output()
	s := strings.TrimSpace(string(out))
	if err != nil && s == "" {
		return "unknown"
	}
	if s == "" {
		return "unknown"
	}
	return s
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
			ActiveState: systemdIsActive(ctx, u.Unit),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}
