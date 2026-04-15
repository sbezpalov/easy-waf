package config

import (
	"testing"
	"time"
)

func TestApplySettingsJSONPatch_omittedPreservesPaths(t *testing.T) {
	base := GlobalSettings{
		ACMEStaging:            true,
		SPOEConfigPath:         "/etc/haproxy/crowdsec.cfg",
		HAProxyConfigPath:      "/var/lib/waf/haproxy.cfg",
		HAProxyBinary:          "/usr/sbin/haproxy",
		CrowdSecEngineName:     "crowdsec",
		GeoIPCacheTTL:          Duration(24 * time.Hour),
		ACMERenewalInterval:    Duration(12 * time.Hour),
		ACMEWebrootPath:        "/var/lib/waf/acme",
		IPBlacklistMapPath:     "/var/lib/waf/ip.map",
		IPBLExternalEnabled:    true,
		ManagementAllowedCIDRs: []string{"10.0.0.0/8"},
	}
	patch := []byte(`{"acme_staging":false}`)
	out, err := ApplySettingsJSONPatch(base, patch)
	if err != nil {
		t.Fatal(err)
	}
	if out.ACMEStaging {
		t.Fatal("expected acme_staging patched")
	}
	if out.SPOEConfigPath != base.SPOEConfigPath || out.HAProxyConfigPath != base.HAProxyConfigPath {
		t.Fatalf("paths should be preserved: spoe=%q haproxy=%q", out.SPOEConfigPath, out.HAProxyConfigPath)
	}
	if out.GeoIPCacheTTL != base.GeoIPCacheTTL {
		t.Fatal("geoip ttl should be preserved")
	}
}

func TestApplySettingsJSONPatch_durationString(t *testing.T) {
	base := DefaultSettings("/tmp/state")
	out, err := ApplySettingsJSONPatch(base, []byte(`{"geoip_cache_ttl":"48h","acme_renewal_interval":"6h"}`))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(out.GeoIPCacheTTL) != 48*time.Hour {
		t.Fatalf("geoip: got %v", time.Duration(out.GeoIPCacheTTL))
	}
	if time.Duration(out.ACMERenewalInterval) != 6*time.Hour {
		t.Fatalf("acme renewal: got %v", time.Duration(out.ACMERenewalInterval))
	}
}

func TestApplySettingsJSONPatch_crowdsecKeyEmptyIgnored(t *testing.T) {
	base := GlobalSettings{CrowdSecLAPIKey: "secret"}
	out, err := ApplySettingsJSONPatch(base, []byte(`{"crowdsec_lapi_key":""}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.CrowdSecLAPIKey != "secret" {
		t.Fatal("empty lapi key in JSON should not clear existing")
	}
	out2, err := ApplySettingsJSONPatch(base, []byte(`{"crowdsec_lapi_key":"new"}`))
	if err != nil {
		t.Fatal(err)
	}
	if out2.CrowdSecLAPIKey != "new" {
		t.Fatalf("got %q", out2.CrowdSecLAPIKey)
	}
}

func TestApplySettingsJSONPatch_unknownKeysIgnored(t *testing.T) {
	base := DefaultSettings("/x")
	out, err := ApplySettingsJSONPatch(base, []byte(`{"future_field":true,"acme_email":"a@b"}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.ACMEEmail != "a@b" {
		t.Fatal(out.ACMEEmail)
	}
}

func TestApplySettingsJSONPatch_trailingDataRejected(t *testing.T) {
	base := DefaultSettings("/x")
	_, err := ApplySettingsJSONPatch(base, []byte(`{}[]`))
	if err == nil {
		t.Fatal("expected error")
	}
}
