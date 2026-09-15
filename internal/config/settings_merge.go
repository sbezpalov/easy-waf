// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ApplySettingsJSONPatch merges a JSON object over base. Only keys present in the object are applied;
// omitted keys keep base values. Unknown keys are ignored. The body must be a single JSON object.
func ApplySettingsJSONPatch(base GlobalSettings, body []byte) (GlobalSettings, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil {
		return base, err
	}
	if dec.More() {
		return base, fmt.Errorf("settings JSON: trailing data after object")
	}
	out := base
	for k, raw := range m {
		if err := patchGlobalSettingKey(&out, k, raw); err != nil {
			return base, fmt.Errorf("%s: %w", k, err)
		}
	}
	return out, nil
}

func patchGlobalSettingKey(out *GlobalSettings, k string, raw json.RawMessage) error {
	switch k {
	case "acme_email":
		return json.Unmarshal(raw, &out.ACMEEmail)
	case "acme_staging":
		return json.Unmarshal(raw, &out.ACMEStaging)
	case "crowdsec_lapi_url":
		return json.Unmarshal(raw, &out.CrowdSecLAPIURL)
	case "crowdsec_lapi_key":
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if v != "" {
			out.CrowdSecLAPIKey = v
		}
		return nil
	case "spoe_config_path":
		return json.Unmarshal(raw, &out.SPOEConfigPath)
	case "haproxy_config_path":
		return json.Unmarshal(raw, &out.HAProxyConfigPath)
	case "haproxy_stats_socket_path":
		return json.Unmarshal(raw, &out.HAProxyStatsSocketPath)
	case "haproxy_binary":
		return json.Unmarshal(raw, &out.HAProxyBinary)
	case "crowdsec_engine_name":
		return json.Unmarshal(raw, &out.CrowdSecEngineName)
	case "geoip_cache_ttl":
		return json.Unmarshal(raw, &out.GeoIPCacheTTL)
	case "geoip_enabled":
		return json.Unmarshal(raw, &out.GeoIPEnabled)
	case "geoip_provider":
		return json.Unmarshal(raw, &out.GeoIPProvider)
	case "geoip_mmdb_path":
		return json.Unmarshal(raw, &out.GeoIPMMDBPath)
	case "geoip_default_policy":
		return json.Unmarshal(raw, &out.GeoIPDefaultPolicy)
	case "geoip_country_list":
		return json.Unmarshal(raw, &out.GeoIPCountryList)
	case "geoip_enforce_map_path":
		return json.Unmarshal(raw, &out.GeoIPEnforceMapPath)
	case "acme_renewal_interval":
		return json.Unmarshal(raw, &out.ACMERenewalInterval)
	case "acme_webroot_path":
		return json.Unmarshal(raw, &out.ACMEWebrootPath)
	case "acme_internal_http":
		return json.Unmarshal(raw, &out.ACMEInternalHTTP)
	case "ip_blacklist_map_path":
		return json.Unmarshal(raw, &out.IPBlacklistMapPath)
	case "ipbl_external_enabled":
		return json.Unmarshal(raw, &out.IPBLExternalEnabled)
	case "ipbl_fetch_allowed_cidrs":
		return json.Unmarshal(raw, &out.IPBLFetchAllowedCIDRs)
	case "ipbl_allow_private_fetch":
		return json.Unmarshal(raw, &out.IPBLAllowPrivateFetch)
	case "acme_dns_resolvers":
		return json.Unmarshal(raw, &out.ACMEDNSResolvers)
	case "ip_allowlist_map_path":
		return json.Unmarshal(raw, &out.IPAllowlistMapPath)
	case "ipwl_enabled":
		return json.Unmarshal(raw, &out.IPWLEnabled)
	case "waf_basic_rules_enabled":
		return json.Unmarshal(raw, &out.WAFBasicRulesEnabled)
	case "block_empty_ua":
		return json.Unmarshal(raw, &out.BlockEmptyUA)
	case "blocked_user_agents_map_path":
		return json.Unmarshal(raw, &out.BlockedUserAgentsMapPath)
	case "blocked_user_agents_enabled":
		return json.Unmarshal(raw, &out.BlockedUserAgentsEnabled)
	case "management_allowed_cidrs":
		return json.Unmarshal(raw, &out.ManagementAllowedCIDRs)
	case "prometheus_enabled":
		return json.Unmarshal(raw, &out.PrometheusEnabled)
	default:
		return nil
	}
}
