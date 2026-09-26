// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package systemd

import "github.com/easy-waf/easy-waf/internal/host/systemdallow"

// AllowedUnits is re-exported for API compatibility.
var AllowedUnits = systemdallow.AllowedUnits

// AllowedUnit reports whether unit is on the appliance whitelist.
func AllowedUnit(unit string) bool {
	return systemdallow.AllowedUnit(unit)
}

// AllowedAction reports whether action is on the appliance whitelist.
func AllowedAction(action string) bool {
	return systemdallow.AllowedAction(action)
}

// AllowedUnitAction reports whether action may be applied to unit.
func AllowedUnitAction(unit, action string) bool {
	return systemdallow.AllowedUnitAction(unit, action)
}
