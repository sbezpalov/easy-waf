// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
)

// SecurityMode is a one-click preset for per-application protection layers.
type SecurityMode string

const (
	ModeFull             SecurityMode = "full"
	ModeBalanced         SecurityMode = "balanced"
	ModeTrustedLAN       SecurityMode = "trusted-lan"
	ModeReverseProxyOnly SecurityMode = "reverse-proxy-only"
	ModeCustom           SecurityMode = "custom"
)

type securityToggleSnapshot struct {
	rate, pathACL, method, waf, bot, ipbl, ipwl, geo, cs bool
}

func snapshot(sec config.ApplicationSecurity) securityToggleSnapshot {
	return securityToggleSnapshot{
		sec.RateLimitEnabled,
		sec.PathACLEnabled,
		sec.MethodFilterEnabled,
		sec.BasicWAFEnabled,
		sec.BotProtectionEnabled,
		sec.IPBlacklistEnabled,
		sec.IPAllowlistEnabled,
		sec.GeoIPEnabled,
		sec.CrowdSecEnabled,
	}
}

func (a securityToggleSnapshot) eq(b securityToggleSnapshot) bool {
	return a == b
}

// ApplyMode sets security toggles from a preset. ModeCustom leaves toggles unchanged.
func ApplyMode(sec *config.ApplicationSecurity, mode SecurityMode) {
	sec.Mode = string(mode)
	switch mode {
	case ModeFull:
		sec.RateLimitEnabled = true
		sec.PathACLEnabled = true
		sec.MethodFilterEnabled = true
		sec.BasicWAFEnabled = true
		sec.BotProtectionEnabled = true
		sec.IPBlacklistEnabled = true
		sec.IPAllowlistEnabled = true
		sec.GeoIPEnabled = true
		sec.CrowdSecEnabled = true
	case ModeBalanced:
		sec.RateLimitEnabled = true
		sec.PathACLEnabled = true
		sec.MethodFilterEnabled = true
		sec.BasicWAFEnabled = true
		sec.BotProtectionEnabled = true
		sec.IPBlacklistEnabled = true
		sec.IPAllowlistEnabled = true
		sec.GeoIPEnabled = false
		sec.CrowdSecEnabled = true
	case ModeTrustedLAN:
		sec.RateLimitEnabled = true
		sec.PathACLEnabled = false
		sec.MethodFilterEnabled = true
		sec.BasicWAFEnabled = false
		sec.BotProtectionEnabled = false
		sec.IPBlacklistEnabled = true
		sec.IPAllowlistEnabled = true
		sec.GeoIPEnabled = false
		sec.CrowdSecEnabled = true
	case ModeReverseProxyOnly:
		sec.RateLimitEnabled = false
		sec.PathACLEnabled = false
		sec.MethodFilterEnabled = false
		sec.BasicWAFEnabled = false
		sec.BotProtectionEnabled = false
		sec.IPBlacklistEnabled = false
		sec.IPAllowlistEnabled = false
		sec.GeoIPEnabled = false
		sec.CrowdSecEnabled = false
	case ModeCustom:
		sec.Mode = string(ModeCustom)
	default:
		sec.Mode = string(ModeCustom)
	}
}

// ApplyModePreset applies toggles and updates Application.Profile for built-in presets.
func ApplyModePreset(a *config.Application, mode SecurityMode) {
	ApplyMode(&a.Security, mode)
	switch mode {
	case ModeFull:
		a.Profile = string(Strict)
	case ModeBalanced:
		a.Profile = string(Balanced)
	case ModeTrustedLAN:
		a.Profile = string(TrustedLAN)
	case ModeReverseProxyOnly, ModeCustom:
	}
}

// DetectMode returns which preset matches the current toggle set, or ModeCustom.
func DetectMode(sec config.ApplicationSecurity) SecurityMode {
	s := snapshot(sec)
	presets := []struct {
		mode SecurityMode
		snap securityToggleSnapshot
	}{
		{ModeReverseProxyOnly, securityToggleSnapshot{false, false, false, false, false, false, false, false, false}},
		{ModeFull, securityToggleSnapshot{true, true, true, true, true, true, true, true, true}},
		{ModeBalanced, securityToggleSnapshot{true, true, true, true, true, true, true, false, true}},
		{ModeTrustedLAN, securityToggleSnapshot{true, false, true, false, false, true, true, false, true}},
	}
	for _, p := range presets {
		if s.eq(p.snap) {
			return p.mode
		}
	}
	return ModeCustom
}

// ParseSecurityMode normalizes user input for API.
func ParseSecurityMode(s string) (SecurityMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeFull):
		return ModeFull, true
	case string(ModeBalanced):
		return ModeBalanced, true
	case string(ModeTrustedLAN):
		return ModeTrustedLAN, true
	case string(ModeReverseProxyOnly):
		return ModeReverseProxyOnly, true
	case string(ModeCustom):
		return ModeCustom, true
	default:
		return "", false
	}
}
