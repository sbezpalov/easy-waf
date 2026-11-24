// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"context"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/runner"
	"github.com/easy-waf/easy-waf/internal/host/systemdallow"
)

// UnitState is one row for GET /host/services.
type UnitState struct {
	Unit        string `json:"unit"`
	ActiveState string `json:"active_state"`
	Enabled     string `json:"enabled_state,omitempty"`
}

// List returns active/enabled state for allowed units.
func List(ctx context.Context) ([]UnitState, error) {
	return listUnits(ctx, runner.Run), nil
}

type runCommand func(context.Context, time.Duration, string, ...string) ([]byte, error)

func listUnits(ctx context.Context, run runCommand) []UnitState {
	out := make([]UnitState, 0, len(AllowedUnits))
	for _, unit := range AllowedUnits {
		if systemdallow.IsOptionalUnit(unit) {
			if st, found := optionalUnitState(ctx, run, unit); found {
				out = append(out, st)
			}
			continue
		}
		st := UnitState{Unit: unit}
		if b, err := run(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", unit); err == nil {
			st.ActiveState = strings.TrimSpace(string(b))
		} else {
			st.ActiveState = "unknown"
		}
		if b, err := run(ctx, 5*time.Second, "/usr/bin/systemctl", "is-enabled", unit); err == nil {
			st.Enabled = strings.TrimSpace(string(b))
		}
		out = append(out, st)
	}
	return out
}

func optionalUnitState(ctx context.Context, run runCommand, unit string) (UnitState, bool) {
	st := UnitState{Unit: unit, ActiveState: "unknown"}
	out, err := run(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,UnitFileState", unit)
	if err != nil {
		return st, false
	}
	var loadState string
	for line := range strings.SplitSeq(string(out), "\n") {
		property, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch property {
		case "LoadState":
			loadState = value
		case "ActiveState":
			st.ActiveState = value
		case "UnitFileState":
			st.Enabled = value
		}
	}
	return st, loadState != "" && loadState != "not-found"
}

// Action runs start|stop|restart|reload|enable|disable on an allowed unit.
func Action(ctx context.Context, action, unit string) error {
	if !AllowedUnit(unit) {
		return osErr("unit not allowed")
	}
	if !AllowedAction(action) {
		return osErr("action not allowed")
	}
	if !AllowedUnitAction(unit, action) {
		return osErr("action not allowed for this unit")
	}
	_, err := runner.Privileged(ctx, "systemctl", action, unit)
	return err
}

type simpleError string

func (e simpleError) Error() string {
	return string(e)
}

func osErr(msg string) error {
	return simpleError(msg)
}
