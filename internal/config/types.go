// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"path/filepath"
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

	// Unset uses the profile's value. 0 means no limit.
	MaxBodyBytesOverride *int64 `json:"max_body_bytes_override,omitempty"`
	// Unset uses the profile's value.
	BlockMultipartOverride *bool `json:"block_multipart_override,omitempty"`
	// Path prefixes that may still receive multipart requests when they are blocked.
	MultipartAllowedPaths []string `json:"multipart_allowed_paths,omitempty"`
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
		// The body settings alone must not turn the default protections off,
		// so they do not count as "this block is set" and are kept here.
		def := DefaultApplicationSecurity()
		def.MaxBodyBytesOverride = s.MaxBodyBytesOverride
		def.BlockMultipartOverride = s.BlockMultipartOverride
		def.MultipartAllowedPaths = s.MultipartAllowedPaths
		*s = def
		return
	}
	p := strings.ToLower(strings.TrimSpace(s.GeoIPPolicy))
	if p != "deny" {
		s.GeoIPPolicy = "allow"
	}
}

// Application is a published hostname → backend mapping (source of truth fragment).
type Application struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PublicHost   string `json:"public_host"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	BackendHTTPS bool   `json:"backend_https"`
	// BackendTLSVerify is "required" (default for new HTTPS backends) or "none" (legacy override).
	BackendTLSVerify string `json:"backend_tls_verify,omitempty"`
	// BackendTLSCAFile is an allowlisted CA bundle path; empty uses the Ubuntu system bundle.
	BackendTLSCAFile string `json:"backend_tls_ca_file,omitempty"`
	// BackendTLSServerName overrides SNI/verifyhost (DNS name or IP). Empty uses backend_host.
	BackendTLSServerName string `json:"backend_tls_server_name,omitempty"`
	// BackendServers are added next to backend_host:backend_port and share its
	// TLS and health-check settings. A backup server gets traffic only while
	// every other server is down. nil on an update keeps the stored list.
	BackendServers []BackendServer `json:"backend_servers,omitempty"`
	// BackendBalance is empty (roundrobin), roundrobin, leastconn or source.
	BackendBalance string `json:"backend_balance,omitempty"`
	// Maintenance answers every request with a 503 maintenance page, without
	// reaching the backend, except from MaintenanceBypassCIDRs.
	Maintenance            bool     `json:"maintenance"`
	MaintenanceBypassCIDRs []string `json:"maintenance_bypass_cidrs,omitempty"`
	// ForwardAuthURL, when set, asks that auth service (Authelia, ...) about
	// every request; only a 2xx answer reaches the servers (fail closed).
	ForwardAuthURL         string           `json:"forward_auth_url,omitempty"`
	ForwardAuthBypassCIDRs []string         `json:"forward_auth_bypass_cidrs,omitempty"`
	WebSocket              bool             `json:"websocket"`
	HealthPath             string           `json:"health_path,omitempty"`
	PathPrefix             string           `json:"path_prefix,omitempty"`
	RestrictedPaths        []RestrictedPath `json:"restricted_paths,omitempty"`
	// PathPolicy is optional exposure control (allowlist, required headers, per-path timeouts and rate limits).
	// A nil value means the client omitted it. On update the API keeps the stored policy.
	PathPolicy    *PathPolicy `json:"path_policy,omitempty"`
	Profile       string      `json:"profile"`
	CertificateID string      `json:"certificate_id,omitempty"`
	// ListenMode controls publishing on fe_http / fe_https: https_only (default), http_only, http_and_https, redirect_to_https.
	ListenMode string              `json:"listen_mode,omitempty"`
	Enabled    bool                `json:"enabled"`
	Security   ApplicationSecurity `json:"security"`
	CreatedAt  time.Time           `json:"created_at"`
	UpdatedAt  time.Time           `json:"updated_at"`
}

// TCPService forwards one TCP port to a backend, optionally only from AllowCIDRs.
type TCPService struct {
	Name        string   `json:"name"`
	ListenPort  int      `json:"listen_port"`
	BackendHost string   `json:"backend_host"`
	BackendPort int      `json:"backend_port"`
	AllowCIDRs  []string `json:"allow_cidrs,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// MaxTCPServices caps tcp_services.
const MaxTCPServices = 32

// TLSPassthrough sends TLS connections on :443 whose SNI is ServerName
// (exact, or "*.domain" for any subdomain) to a backend without decrypting
// them. SendProxy prefixes each connection with PROXY protocol v2.
type TLSPassthrough struct {
	ServerName  string   `json:"server_name"`
	BackendHost string   `json:"backend_host"`
	BackendPort int      `json:"backend_port"`
	SendProxy   bool     `json:"send_proxy,omitempty"`
	AllowCIDRs  []string `json:"allow_cidrs,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// MaxTLSPassthrough caps tls_passthrough.
const MaxTLSPassthrough = 32

// ReservedTCPPorts cannot be a tcp_services listen_port: SSH, the edge, the
// management listeners, the ACME helper and the CrowdSec bouncer.
var ReservedTCPPorts = map[int]bool{22: true, 80: true, 443: true, 8000: true, 8089: true, 8443: true, 9000: true}

// BackendServer is one extra server behind an application.
type BackendServer struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Backup bool   `json:"backup,omitempty"`
}

// MaxBackendServers caps backend_servers (the primary server comes on top).
const MaxBackendServers = 15

// BackendBalances are the accepted backend_balance values.
var BackendBalances = []string{"", "roundrobin", "leastconn", "source"}

// Certificate stores metadata for HAProxy PEM material.
type Certificate struct {
	ID            string   `json:"id"`
	PrimaryDomain string   `json:"primary_domain"`
	SAN           []string `json:"san,omitempty"`
	Mode          string   `json:"mode"` // http-01, dns-01, self-signed
	// DNSProvider: cloudflare | cloudns (default for dns-01) | route53 | webhook (Lego httpreq).
	DNSProvider           string `json:"dns_provider,omitempty"`
	DNSCredentialsEnvFile string `json:"dns_credentials_env_file,omitempty"` // easy-waf-readable 0600 env file; never store secrets in DB
	// ACMEStatus: ready | pending | issuing | failed (manual / self-signed use ready).
	ACMEStatus string `json:"acme_status,omitempty"`
	// ACMEAttempts counts consecutive failed issuances; ACMENextAttemptAt is when
	// easy-waf-acmed retries a failed row. Both reset on success or a manual request.
	ACMEAttempts      int        `json:"acme_attempts,omitempty"`
	ACMENextAttemptAt *time.Time `json:"acme_next_attempt_at,omitempty"`
	Staging           bool       `json:"staging"`
	PEMCrtPath        string     `json:"pem_crt_path"`
	PEMKeyPath        string     `json:"pem_key_path"`
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
	Status        string     `json:"status"` // valid | expiring | expired | pending | failed
	Mode          string     `json:"mode"`   // http-01 | dns-01 | manual
	// LastError and NextAttemptAt are set while Status is failed.
	LastError     string     `json:"last_error,omitempty"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	// Attention is why an operator should look at this certificate; see CertificateAttention.
	Attention string `json:"attention,omitempty"`
}

// CertificateSummaryResponse aggregates counts and per-certificate rows for dashboards.
type CertificateSummaryResponse struct {
	Total        int                       `json:"total"`
	Valid        int                       `json:"valid"`
	ExpiringSoon int                       `json:"expiring_soon"`
	Expired      int                       `json:"expired"`
	Failed       int                       `json:"failed"`
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
	// ACMEInternalHTTP is the loopback ip:port that serves HTTP-01 token files:
	// easy-waf-api listens on it and the generated bk_acme backend points at it.
	// It lives in settings rather than in the environment because the rendered
	// config must be a function of the database — easy-waf-api, easy-waf-acmed
	// and easy-waf-admin all render, and an address read from each process's own
	// environment could differ between them. Empty means the default
	// (DefaultACMEInternalHTTP). Must be ip:port; see ValidateListenAddr.
	ACMEInternalHTTP string `json:"acme_internal_http,omitempty"`
	// IPBlacklistMapPath is the generated HAProxy src map file (IPv4/IPv6 lines, one per line).
	IPBlacklistMapPath string `json:"ip_blacklist_map_path,omitempty"`
	// IPBLExternalEnabled enables merging synced external lists into the map file.
	IPBLExternalEnabled bool `json:"ipbl_external_enabled"`
	// IPBLFetchAllowedCIDRs allows feed URLs that resolve to private IPs in these prefixes (split-DNS internal feeds).
	IPBLFetchAllowedCIDRs []string `json:"ipbl_fetch_allowed_cidrs,omitempty"`
	// IPBLAllowPrivateFetch is deprecated: use ipbl_fetch_allowed_cidrs; when true and CIDRs empty, allows 10/8, 172.16/12, 192.168/16 only.
	IPBLAllowPrivateFetch bool `json:"ipbl_allow_private_fetch,omitempty"`
	// ACMEDNSResolvers overrides DNS used for ACME DNS-01 propagation checks (e.g. "1.1.1.1:53","8.8.8.8:53").
	ACMEDNSResolvers []string `json:"acme_dns_resolvers,omitempty"`
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
	// NotifyWebhookURL receives a JSON POST when a certificate needs attention
	// (failed issuance or renewal, or fewer than 21 days left). Empty disables it.
	// The URL is not written into HAProxy config and is not logged.
	NotifyWebhookURL string `json:"notify_webhook_url,omitempty"`
	// NotifyTelegramChatID and NotifyTelegramBotToken also send notifications to
	// a Telegram chat. The API never returns the token; clearing the chat ID
	// clears it.
	NotifyTelegramChatID   string `json:"notify_telegram_chat_id,omitempty"`
	NotifyTelegramBotToken string `json:"notify_telegram_bot_token,omitempty"`
	// NotifyBlockedSpikeThreshold alerts when the edge refuses at least this
	// many requests within 5 minutes. 0 turns the alert off.
	NotifyBlockedSpikeThreshold int `json:"notify_blocked_spike_threshold"`
	// TCPServices publishes raw TCP ports (MQTT, RTSP, ...) through HAProxy
	// mode tcp. The host firewall must allow each listen_port.
	TCPServices []TCPService `json:"tcp_services,omitempty"`
	// TLSPassthrough routes listed SNI names on :443 to their own TLS
	// servers, still encrypted; every other connection reaches fe_https.
	TLSPassthrough []TLSPassthrough `json:"tls_passthrough,omitempty"`
	// PrometheusEnabled exposes GET /metrics (Prometheus text format) for scrapers on the management listener.
	// Not behind a session JWT: protected by management_allowed_cidrs and, when
	// EASY_WAF_METRICS_TOKEN is set, a static bearer token. Default off.
	PrometheusEnabled bool `json:"prometheus_enabled"`
	// ListenIPv6 adds IPv6-only binds on :80 and :443 next to the IPv4 ones.
	// The host must have IPv6 enabled, or HAProxy cannot bind on reload.
	ListenIPv6 bool `json:"listen_ipv6"`
	// HTTP3 adds QUIC binds on UDP :443 to fe_https and advertises them with
	// Alt-Svc. Needs HAProxy built with QUIC and UDP 443 open in the firewall.
	HTTP3 bool `json:"http3"`
	// TrustedProxyCIDRs are the proxies (CDN, NGFW, tunnel) whose RealIPHeader
	// replaces the connection source on the edge. Requests from anywhere else keep
	// their own source, so a client cannot spoof the header.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
	// RealIPHeader names the header carrying the client address; see RealIPHeaders.
	// Empty means X-Forwarded-For. The last occurrence is used.
	RealIPHeader string `json:"real_ip_header,omitempty"`
	// ProxyProtocolCIDRs must send a PROXY protocol v1/v2 header on :80 and :443.
	// Connections from other sources are accepted without one.
	ProxyProtocolCIDRs []string `json:"proxy_protocol_cidrs,omitempty"`
	// SecurityHeadersEnabled adds X-Content-Type-Options and Referrer-Policy
	// when the backend did not set them, and removes Server and X-Powered-By.
	SecurityHeadersEnabled bool `json:"security_headers_enabled"`
	// HSTSIncludeSubdomains adds includeSubDomains to Strict-Transport-Security.
	// Off by default: it would force HTTPS on any plain-HTTP host below a
	// published one.
	HSTSIncludeSubdomains bool `json:"hsts_include_subdomains"`
}

// RealIPHeaders are the accepted values of GlobalSettings.RealIPHeader.
var RealIPHeaders = []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"}

// RealIPHeaderOrDefault resolves an empty RealIPHeader to X-Forwarded-For.
func RealIPHeaderOrDefault(h string) string {
	if strings.TrimSpace(h) == "" {
		return "X-Forwarded-For"
	}
	return h
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
	// Generated HAProxy paths use forward slashes on every development host.
	stateDir = filepath.ToSlash(stateDir)
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
		ACMEInternalHTTP:         DefaultACMEInternalHTTP,
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
		SecurityHeadersEnabled:   true,
	}
}
