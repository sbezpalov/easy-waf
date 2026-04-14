package config

import "time"

// Application is a published hostname → backend mapping (source of truth fragment).
type Application struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PublicHost   string `json:"public_host"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	BackendHTTPS bool   `json:"backend_https"`
	WebSocket    bool   `json:"websocket"`
	HealthPath   string `json:"health_path,omitempty"`
	PathPrefix   string `json:"path_prefix,omitempty"`
	Profile      string `json:"profile"`
	CertificateID string `json:"certificate_id,omitempty"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Certificate stores metadata for HAProxy PEM material.
type Certificate struct {
	ID         string    `json:"id"`
	PrimaryDomain string `json:"primary_domain"`
	SAN        []string  `json:"san,omitempty"`
	Mode       string `json:"mode"` // http-01, dns-01, self-signed
	// DNSProvider: cloudflare | cloudns (default for dns-01) | route53 | webhook (Lego httpreq).
	DNSProvider           string `json:"dns_provider,omitempty"`
	DNSCredentialsEnvFile string `json:"dns_credentials_env_file,omitempty"` // root-readable env file; never store secrets in DB
	// ACMEStatus: ready | pending | issuing | failed (manual / self-signed use ready).
	ACMEStatus string `json:"acme_status,omitempty"`
	Staging    bool      `json:"staging"`
	PEMCrtPath string    `json:"pem_crt_path"`
	PEMKeyPath string    `json:"pem_key_path"`
	// BundlePath is fullchain + private key in one PEM for HAProxy crt/crt-list (preferred).
	BundlePath    string `json:"bundle_path,omitempty"`
	FullchainPath string `json:"fullchain_path,omitempty"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// GlobalSettings controls daemon and edge defaults.
type GlobalSettings struct {
	ACMEEmail           string `json:"acme_email,omitempty"`
	ACMEStaging         bool   `json:"acme_staging"`
	CrowdSecLAPIURL     string `json:"crowdsec_lapi_url,omitempty"`
	CrowdSecLAPIKey     string `json:"-"` // never serialize to JSON in logs by default
	SPOEConfigPath      string `json:"spoe_config_path"`
	HAProxyConfigPath   string `json:"haproxy_config_path"`
	HAProxyBinary       string `json:"haproxy_binary"`
	CrowdSecEngineName  string `json:"crowdsec_engine_name"`
	GeoIPCacheTTL       time.Duration `json:"geoip_cache_ttl"`
	ACMERenewalInterval time.Duration `json:"acme_renewal_interval"`
	// ACMEWebrootPath is the filesystem root for HTTP-01 challenges (HAProxy must expose /.well-known/ → this path).
	ACMEWebrootPath string `json:"acme_webroot_path,omitempty"`
	// IPBlacklistMapPath is the generated HAProxy src map file (IPv4/IPv6 lines, one per line).
	IPBlacklistMapPath string `json:"ip_blacklist_map_path,omitempty"`
	// IPBLExternalEnabled enables merging synced external lists into the map file.
	IPBLExternalEnabled bool `json:"ipbl_external_enabled"`
	// ManagementAllowedCIDRs restricts who can reach the API and UI (not /health).
	// Stored in DB; defaults are RFC1918 + loopback — narrow in Settings for stricter policy.
	ManagementAllowedCIDRs []string `json:"management_allowed_cidrs,omitempty"`
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
		ACMEStaging:            true,
		SPOEConfigPath:         "/etc/haproxy/crowdsec.cfg",
		HAProxyConfigPath:      stateDir + "/haproxy/haproxy.cfg",
		HAProxyBinary:          "/usr/sbin/haproxy",
		CrowdSecEngineName:     "crowdsec",
		GeoIPCacheTTL:          24 * time.Hour,
		ACMERenewalInterval:    12 * time.Hour,
		ACMEWebrootPath:        stateDir + "/acme/webroot",
		IPBlacklistMapPath:     stateDir + "/haproxy/ip_blacklist.map",
		IPBLExternalEnabled:    true,
		ManagementAllowedCIDRs: DefaultManagementCIDRs(),
	}
}
