package config

import (
	"encoding/json"
	"strings"
	"time"
)

// AuditLogEntry is one row from PostgreSQL audit_log (API / UI).
type AuditLogEntry struct {
	ID        int64           `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	UserName  string          `json:"user_name"`
	Action    string          `json:"action"`
	Details   json.RawMessage `json:"details"`
	SourceIP  string          `json:"source_ip"`
}

// RestrictedPath limits a path prefix on an app to requests from AllowedCIDRs only (LAN-style).
type RestrictedPath struct {
	PathPrefix   string   `json:"path_prefix"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
}

// ApplicationSecurity holds per-application protection toggles and GeoIP overrides.
type ApplicationSecurity struct {
	Mode string `json:"mode"` // full | balanced | trusted-lan | reverse-proxy-only | custom

	RateLimitEnabled     bool `json:"rate_limit_enabled"`
	PathACLEnabled       bool `json:"path_acl_enabled"`
	MethodFilterEnabled  bool `json:"method_filter_enabled"`
	BasicWAFEnabled      bool `json:"basic_waf_enabled"`
	BotProtectionEnabled bool `json:"bot_protection_enabled"`
	IPBlacklistEnabled   bool `json:"ip_blacklist_enabled"`
	IPAllowlistEnabled   bool `json:"ip_allowlist_enabled"`
	GeoIPEnabled         bool `json:"geoip_enabled"`
	CrowdSecEnabled      bool `json:"crowdsec_enabled"`

	GeoIPPolicy      string   `json:"geoip_policy"`       // allow | deny
	GeoIPCountryList []string `json:"geoip_country_list"` // ISO 3166-1 alpha-2

	RateLimitRPSOverride   *int `json:"rate_limit_rps_override,omitempty"`
	RateLimitBurstOverride *int `json:"rate_limit_burst_override,omitempty"`
}

// DefaultApplicationSecurity is used for new applications and when JSON is missing fields.
func DefaultApplicationSecurity() ApplicationSecurity {
	return ApplicationSecurity{
		Mode:                 "balanced",
		RateLimitEnabled:     true,
		PathACLEnabled:       true,
		MethodFilterEnabled:  true,
		BasicWAFEnabled:      true,
		BotProtectionEnabled: true,
		IPBlacklistEnabled:   true,
		IPAllowlistEnabled:   true,
		GeoIPEnabled:         false,
		CrowdSecEnabled:      true,
		GeoIPPolicy:          "allow",
		GeoIPCountryList:     nil,
	}
}

// NormalizeApplicationSecurity fills legacy zero structs and normalizes GeoIP policy.
func NormalizeApplicationSecurity(s *ApplicationSecurity) {
	if s == nil {
		return
	}
	if strings.TrimSpace(s.Mode) == "" {
		*s = DefaultApplicationSecurity()
		return
	}
	p := strings.ToLower(strings.TrimSpace(s.GeoIPPolicy))
	if p != "deny" {
		s.GeoIPPolicy = "allow"
	}
}

// Application is a published hostname → backend mapping (source of truth fragment).
type Application struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	PublicHost      string           `json:"public_host"`
	BackendHost     string           `json:"backend_host"`
	BackendPort     int              `json:"backend_port"`
	BackendHTTPS    bool             `json:"backend_https"`
	WebSocket       bool             `json:"websocket"`
	HealthPath      string           `json:"health_path,omitempty"`
	PathPrefix      string           `json:"path_prefix,omitempty"`
	RestrictedPaths []RestrictedPath `json:"restricted_paths,omitempty"`
	Profile         string           `json:"profile"`
	CertificateID   string           `json:"certificate_id,omitempty"`
	// ListenMode controls publishing on fe_http / fe_https: https_only (default), http_only, http_and_https, redirect_to_https.
	ListenMode string              `json:"listen_mode,omitempty"`
	Enabled    bool                `json:"enabled"`
	Security   ApplicationSecurity `json:"security"`
	CreatedAt  time.Time           `json:"created_at"`
	UpdatedAt  time.Time           `json:"updated_at"`
}

// Certificate stores metadata for HAProxy PEM material.
type Certificate struct {
	ID            string   `json:"id"`
	PrimaryDomain string   `json:"primary_domain"`
	SAN           []string `json:"san,omitempty"`
	Mode          string   `json:"mode"` // http-01, dns-01, self-signed
	// DNSProvider: cloudflare | cloudns (default for dns-01) | route53 | webhook (Lego httpreq).
	DNSProvider           string `json:"dns_provider,omitempty"`
	DNSCredentialsEnvFile string `json:"dns_credentials_env_file,omitempty"` // root-readable env file; never store secrets in DB
	// ACMEStatus: ready | pending | issuing | failed (manual / self-signed use ready).
	ACMEStatus string `json:"acme_status,omitempty"`
	Staging    bool   `json:"staging"`
	PEMCrtPath string `json:"pem_crt_path"`
	PEMKeyPath string `json:"pem_key_path"`
	// BundlePath is fullchain + private key in one PEM for HAProxy crt/crt-list (preferred).
	BundlePath    string     `json:"bundle_path,omitempty"`
	FullchainPath string     `json:"fullchain_path,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// CertificateSummaryEntry is one row for GET /api/v1/certificates/summary (dashboard + UI).
type CertificateSummaryEntry struct {
	ID            string     `json:"id"`
	PrimaryDomain string     `json:"primary_domain"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	DaysRemaining *int       `json:"days_remaining,omitempty"`
	Status        string     `json:"status"` // valid | expiring | expired | pending
	Mode          string     `json:"mode"`   // http-01 | dns-01 | manual
}

// CertificateSummaryResponse aggregates counts and per-certificate rows for dashboards.
type CertificateSummaryResponse struct {
	Total        int                       `json:"total"`
	Valid        int                       `json:"valid"`
	ExpiringSoon int                       `json:"expiring_soon"`
	Expired      int                       `json:"expired"`
	Certificates []CertificateSummaryEntry `json:"certificates"`
}

// GlobalSettings controls daemon and edge defaults.
type GlobalSettings struct {
	ACMEEmail         string `json:"acme_email,omitempty"`
	ACMEStaging       bool   `json:"acme_staging"`
	CrowdSecLAPIURL   string `json:"crowdsec_lapi_url,omitempty"`
	CrowdSecLAPIKey   string `json:"-"` // never serialize to JSON in logs by default
	SPOEConfigPath    string `json:"spoe_config_path"`
	HAProxyConfigPath string `json:"haproxy_config_path"`
	// HAProxyStatsSocketPath is the Unix socket for "show stat" (runtime metrics). Default: /run/haproxy/easy-waf-admin.sock.
	HAProxyStatsSocketPath string   `json:"haproxy_stats_socket_path,omitempty"`
	HAProxyBinary          string   `json:"haproxy_binary"`
	CrowdSecEngineName     string   `json:"crowdsec_engine_name"`
	GeoIPCacheTTL          Duration `json:"geoip_cache_ttl"`
	// GeoIPEnabled turns on batch GeoIP map generation on apply/sync and optional HAProxy fe_https deny ACL.
	GeoIPEnabled bool `json:"geoip_enabled"`
	// GeoIPProvider: "ipinfo" (default) or "maxmind" (local GeoLite2-Country MMDB).
	GeoIPProvider string `json:"geoip_provider,omitempty"`
	// GeoIPMMDBPath is the filesystem path to GeoLite2-Country.mmdb (or compatible) when GeoIPProvider is maxmind.
	GeoIPMMDBPath string `json:"geoip_mmdb_path,omitempty"`
	// GeoIPDefaultPolicy: "allow" = allow-list; "deny" = deny-list (see docs/ARCHITECTURE.md GeoIP).
	GeoIPDefaultPolicy string `json:"geoip_default_policy,omitempty"`
	// GeoIPCountryList is ISO 3166-1 alpha-2 codes, e.g. ["US","DE"].
	GeoIPCountryList []string `json:"geoip_country_list,omitempty"`
	// GeoIPEnforceMapPath is the HAProxy src map of CIDRs to deny for GeoIP batch enforcement.
	GeoIPEnforceMapPath string   `json:"geoip_enforce_map_path,omitempty"`
	ACMERenewalInterval Duration `json:"acme_renewal_interval"`
	// ACMEWebrootPath is the filesystem root for HTTP-01 challenges (HAProxy must expose /.well-known/ → this path).
	ACMEWebrootPath string `json:"acme_webroot_path,omitempty"`
	// IPBlacklistMapPath is the generated HAProxy src map file (IPv4/IPv6 lines, one per line).
	IPBlacklistMapPath string `json:"ip_blacklist_map_path,omitempty"`
	// IPBLExternalEnabled enables merging synced external lists into the map file.
	IPBLExternalEnabled bool `json:"ipbl_external_enabled"`
	// IPAllowlistMapPath is the generated HAProxy src map for trusted CIDRs (see docs/IPBL.md).
	IPAllowlistMapPath string `json:"ip_allowlist_map_path,omitempty"`
	// IPWLEnabled turns on HAProxy ACL + http-request allow for sources in the allowlist map.
	IPWLEnabled bool `json:"ipwl_enabled"`
	// WAFBasicRulesEnabled adds HAProxy fe_https regex ACLs for basic SQLi/XSS/path traversal (after IP ACLs).
	WAFBasicRulesEnabled bool `json:"waf_basic_rules_enabled"`
	// BlockEmptyUA denies requests with empty User-Agent on fe_https (after IP allowlist).
	BlockEmptyUA bool `json:"block_empty_ua"`
	// BlockedUserAgentsMapPath is the generated map file (one substring per line) for -m sub -f matching.
	BlockedUserAgentsMapPath string `json:"blocked_user_agents_map_path,omitempty"`
	// BlockedUserAgentsEnabled turns on HAProxy deny for User-Agent substrings from the map file.
	BlockedUserAgentsEnabled bool `json:"blocked_user_agents_enabled"`
	// ManagementAllowedCIDRs restricts who can reach the API and UI (not /health).
	// Stored in DB; defaults are RFC1918 + loopback — narrow in Settings for stricter policy.
	ManagementAllowedCIDRs []string `json:"management_allowed_cidrs,omitempty"`
	// PrometheusEnabled exposes GET /metrics (Prometheus text format) for scrapers on the management listener.
	// Protected by management_allowed_cidrs only (no JWT). Default off.
	PrometheusEnabled bool `json:"prometheus_enabled"`
}

// DefaultManagementCIDRs is the bootstrap allowlist for the control plane (LAN + loopback).
func DefaultManagementCIDRs() []string {
	return []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
}

// DefaultSettings returns safe defaults for development and docs.
func DefaultSettings(stateDir string) GlobalSettings {
	return GlobalSettings{
		ACMEStaging:              true,
		SPOEConfigPath:           "/etc/haproxy/crowdsec.cfg",
		HAProxyConfigPath:        stateDir + "/haproxy/haproxy.cfg",
		HAProxyStatsSocketPath:   "/run/haproxy/easy-waf-admin.sock",
		HAProxyBinary:            "/usr/sbin/haproxy",
		CrowdSecLAPIURL:          "http://127.0.0.1:8080/",
		CrowdSecEngineName:       "crowdsec",
		GeoIPCacheTTL:            Duration(24 * time.Hour),
		GeoIPEnabled:             false,
		GeoIPProvider:            "ipinfo",
		GeoIPDefaultPolicy:       "allow",
		GeoIPCountryList:         nil,
		GeoIPEnforceMapPath:      stateDir + "/haproxy/geoip_enforce.map",
		ACMERenewalInterval:      Duration(12 * time.Hour),
		ACMEWebrootPath:          stateDir + "/acme/webroot",
		IPBlacklistMapPath:       stateDir + "/haproxy/ip_blacklist.map",
		IPBLExternalEnabled:      true,
		IPAllowlistMapPath:       stateDir + "/haproxy/ip_allowlist.map",
		IPWLEnabled:              false,
		WAFBasicRulesEnabled:     true,
		BlockEmptyUA:             true,
		BlockedUserAgentsMapPath: stateDir + "/haproxy/blocked_ua.map",
		BlockedUserAgentsEnabled: false,
		ManagementAllowedCIDRs:   DefaultManagementCIDRs(),
		PrometheusEnabled:        false,
	}
}
