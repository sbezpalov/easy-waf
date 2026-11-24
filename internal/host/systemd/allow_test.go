// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestAllowedUnit_matchesPrivilegedScriptList(t *testing.T) {
	want := []string{
		"easy-waf-api.service",
		"easy-waf-acmed.service",
		"haproxy.service",
		"crowdsec.service",
		"crowdsec-spoa-bouncer.service",
		"fail2ban.service",
		"nftables.service",
		"postgresql.service",
		"zabbix-agent.service",
		"zabbix-agent2.service",
	}
	if len(want) != len(AllowedUnits) {
		t.Fatalf("AllowedUnits len %d want %d", len(AllowedUnits), len(want))
	}
	for _, u := range want {
		if !AllowedUnit(u) {
			t.Fatalf("AllowedUnit(%q) false", u)
		}
	}
	if AllowedUnit("ssh.service") {
		t.Fatal("ssh.service must not be allowed")
	}
}

func TestListUnitsDetectsOptionalZabbixServices(t *testing.T) {
	for _, tc := range []struct {
		name  string
		older string
		newer string
		want  []UnitState
	}{
		{name: "neither installed"},
		{
			name: "classic agent installed but disabled", older: "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n",
			want: []UnitState{{Unit: "zabbix-agent.service", ActiveState: "inactive", Enabled: "disabled"}},
		},
		{
			name: "agent 2 installed and active", newer: "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n",
			want: []UnitState{{Unit: "zabbix-agent2.service", ActiveState: "active", Enabled: "enabled"}},
		},
		{
			name:  "both detected with a masked agent",
			older: "LoadState=masked\nActiveState=inactive\nUnitFileState=masked\n",
			newer: "LoadState=loaded\nActiveState=failed\nUnitFileState=disabled\n",
			want: []UnitState{
				{Unit: "zabbix-agent.service", ActiveState: "inactive", Enabled: "masked"},
				{Unit: "zabbix-agent2.service", ActiveState: "failed", Enabled: "disabled"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := listUnits(t.Context(), func(_ context.Context, _ time.Duration, path string, args ...string) ([]byte, error) {
				unit := args[len(args)-1]
				var state string
				switch unit {
				case "zabbix-agent.service":
					state = tc.older
					if state == "" {
						state = "LoadState=not-found\nActiveState=inactive\n"
					}
				case "zabbix-agent2.service":
					state = tc.newer
				default:
					return []byte("fixture\n"), nil
				}
				if path != "/usr/bin/systemctl" || !slices.Equal(args, []string{"show", "--property=LoadState,ActiveState,UnitFileState", unit}) {
					t.Fatalf("unexpected discovery command: %s %q", path, args)
				}
				if state == "" {
					return nil, errors.New("unit could not be found")
				}
				return []byte(state), nil
			})
			const baseServices = 8
			if len(got) < baseServices || !slices.Equal(got[baseServices:], tc.want) {
				t.Fatalf("services = %+v, want existing services and %+v", got, tc.want)
			}
		})
	}
}

func TestAllowedAction_matchesPrivilegedScriptList(t *testing.T) {
	for _, a := range []string{"start", "stop", "restart", "reload", "enable", "disable", "try-restart"} {
		if !AllowedAction(a) {
			t.Fatalf("AllowedAction(%q) false", a)
		}
	}
	for _, a := range []string{"mask", "kill", "daemon-reload"} {
		if AllowedAction(a) {
			t.Fatalf("AllowedAction(%q) should be false", a)
		}
	}
}
