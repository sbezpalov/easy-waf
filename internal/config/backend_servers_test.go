// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateBackendServers(t *testing.T) {
	base := Application{BackendHost: "10.0.0.1", BackendPort: 80}
	ok := base
	ok.BackendBalance = "leastconn"
	ok.BackendServers = []BackendServer{{Host: "10.0.0.2", Port: 80}, {Host: "standby.lan", Port: 8080, Backup: true}}
	if err := validateBackendServers(&ok); err != nil {
		t.Fatal(err)
	}
	many := base
	for i := 0; i <= MaxBackendServers; i++ {
		many.BackendServers = append(many.BackendServers, BackendServer{Host: "10.0.1.1", Port: 1000 + i})
	}
	cases := map[string]Application{
		"balance":   {BackendHost: "10.0.0.1", BackendPort: 80, BackendBalance: "random"},
		"host":      {BackendHost: "10.0.0.1", BackendPort: 80, BackendServers: []BackendServer{{Host: "a b", Port: 80}}},
		"injection": {BackendHost: "10.0.0.1", BackendPort: 80, BackendServers: []BackendServer{{Host: "x\n\tserver y", Port: 80}}},
		"port":      {BackendHost: "10.0.0.1", BackendPort: 80, BackendServers: []BackendServer{{Host: "10.0.0.2", Port: 0}}},
		"primary":   {BackendHost: "10.0.0.1", BackendPort: 80, BackendServers: []BackendServer{{Host: "10.0.0.1", Port: 80}}},
		"twice":     {BackendHost: "10.0.0.1", BackendPort: 80, BackendServers: []BackendServer{{Host: "A.lan", Port: 1}, {Host: "a.lan", Port: 1}}},
		"many":      many,
	}
	for name, app := range cases {
		app := app
		if err := validateBackendServers(&app); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "twice" && !strings.Contains(err.Error(), "twice") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMaintenanceBypassValidation(t *testing.T) {
	app := Application{Name: "a", PublicHost: "a.example.com", BackendHost: "10.0.0.1", BackendPort: 80, Maintenance: true,
		MaintenanceBypassCIDRs: []string{"192.168.1.0/24", "fd00::1"}}
	if err := ValidateApplicationRenderSafety(&app); err != nil {
		t.Fatal(err)
	}
	app.MaintenanceBypassCIDRs = []string{"192.168.1.0/24 } || { always_true"}
	if err := ValidateApplicationRenderSafety(&app); err == nil {
		t.Fatal("accepted an injected bypass entry")
	}
}
