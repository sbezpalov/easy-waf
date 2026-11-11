// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// AppRender pairs an enabled application with its resolved profile for templating.
type AppRender struct {
	Application       config.Application
	Profile           profiles.Profile
	ACLTag            string
	GeoEnforceMapPath string
	UsePerAppGeo      bool
	RateLimitBurst    int
	BackendUsesDNS    bool // a server host is an FQDN — the config needs resolvers easy_waf_dns
	Servers           []ServerRender
	// MaintenanceBypassSrc is maintenance_bypass_cidrs joined for `src`.
	MaintenanceBypassSrc string
	// ForwardAuthBypassSrc is forward_auth_bypass_cidrs joined for `src`.
	ForwardAuthBypassSrc string
	MaxBodyBytes         int64
	BlockMultipart       bool
	Exposure             pathExposure
}

// TCPServiceRender is one enabled tcp_services entry.
type TCPServiceRender struct {
	config.TCPService
	AllowSrc string
	UsesDNS  bool
}

// TLSPassthroughRender is one enabled tls_passthrough entry.
type TLSPassthroughRender struct {
	config.TLSPassthrough
	Backend  string
	Match    string // fe_tls_in condition on the ClientHello SNI
	AllowSrc string
	UsesDNS  bool
}

// ServerRender is one `server` line of an application backend.
type ServerRender struct {
	Name    string
	Host    string
	Port    int
	TLS     string
	UsesDNS bool
	Backup  bool
}

func appServers(app config.Application) []ServerRender {
	out := make([]ServerRender, 0, 1+len(app.BackendServers))
	out = append(out, ServerRender{Name: "s1", Host: app.BackendHost, Port: app.BackendPort})
	for i, sv := range app.BackendServers {
		out = append(out, ServerRender{Name: fmt.Sprintf("s%d", i+2), Host: sv.Host, Port: sv.Port, Backup: sv.Backup})
	}
	for i := range out {
		out[i].TLS = backendTLSOptions(app, out[i].Host)
		out[i].UsesDNS = !backendHostIsLiteralIP(out[i].Host)
	}
	return out
}

// RenderInput is passed to the HAProxy template.
type RenderInput struct {
	Settings         config.GlobalSettings
	Applications     []config.Application
	BackendApps      []AppRender `json:"-"` // every enabled app (backend definitions)
	HTTPSApps        []AppRender `json:"-"` // fe_https: TLS edge (https_only, redirect_to_https, http_and_https)
	HTTPApps         []AppRender `json:"-"` // fe_http: plain routing (http_only, http_and_https)
	RedirectApps     []AppRender `json:"-"` // fe_http: per-host redirect to HTTPS
	HasHTTPSFrontend bool        `json:"-"` // false when no :443 TLS vhosts (crt-list may still list unused PEMs)
	// HTTPClientTimeout and HTTPSClientTimeout are the longest timeout client
	// any app on that frontend asked for. HAProxy 2.8 cannot change it per
	// request, so the frontend uses one value. Zero keeps the 50s default.
	HTTPClientTimeout        int                           `json:"-"`
	HTTPSClientTimeout       int                           `json:"-"`
	Certificates             map[string]config.Certificate // id -> cert
	CRTListPath              string                        // absolute path to generated crt-list file on disk
	IPBlacklistMapPath       string
	IPAllowlistMapPath       string
	UseIPBlacklist           bool
	UseIPAllowlist           bool
	BlockedUserAgentsMapPath string             // absolute path to generated substring map (-m sub -f)
	UseBlockedUserAgents     bool               // enabled in settings and map has at least one pattern line
	StateDir                 string             // state directory for per-app GeoIP map paths
	UseCrowdSecFilter        bool               // at least one routed app requests CrowdSec and SPOE path is configured
	UseCrowdSecHTTP          bool               // SPOE on fe_http
	UseCrowdSecHTTPS         bool               // SPOE on fe_https
	NeedsDNSResolver         bool               // any backend uses DNS name (split-DNS / DHCP)
	TCPServices              []TCPServiceRender `json:"-"`
	// TLSPassthrough is non-empty when fe_tls_in owns :443; fe_https then
	// listens on HTTPSChainSocket behind it (empty without fe_https).
	TLSPassthrough   []TLSPassthroughRender `json:"-"`
	HTTPSChainSocket string                 `json:"-"`
	// ACMEBackendAddr is the ip:port the generated bk_acme backend points at.
	// Render fills it from Settings.ACMEInternalHTTP; callers do not set it.
	ACMEBackendAddr string `json:"-"`
	// ForwardAuthLuaPath is the forward-auth.lua to load; empty uses
	// DefaultForwardAuthLuaPath. UseForwardAuth is derived by Render.
	ForwardAuthLuaPath string `json:"-"`
	UseForwardAuth     bool   `json:"-"`
	// TrustedProxySrc, ProxyProtocolSrc and RealIPFetch are derived from
	// Settings by Render; callers do not set them.
	TrustedProxySrc  string `json:"-"`
	ProxyProtocolSrc string `json:"-"`
	RealIPFetch      string `json:"-"`
	// HSTSExemptHosts are fe_https hosts that also serve plain HTTP
	// (http_and_https): HSTS there would make browsers refuse the HTTP side.
	HSTSExemptHosts string `json:"-"`
}

// Rendered holds outputs and checksum for apply pipeline.
type Rendered struct {
	HAProxyConfig string
	CRTList       string
	SHA256        string
	// RequiresTLS is false when no fe_https listener is generated (HTTP-only edge); Apply may allow an empty crt-list.
	RequiresTLS bool
}

// Render generates HAProxy configuration and crt-list body.
func Render(in RenderInput) (Rendered, error) {
	if strings.TrimSpace(in.StateDir) == "" && strings.TrimSpace(in.Settings.HAProxyConfigPath) != "" {
		in.StateDir = filepath.Clean(filepath.Join(filepath.Dir(in.Settings.HAProxyConfigPath), ".."))
	}
	// Settings and certificates get the same treatment as applications below:
	// re-checked here, not only where they were written.
	if err := config.ValidateSettingsRenderSafety(&in.Settings); err != nil {
		return Rendered{}, fmt.Errorf("settings are unsafe to render: %w", err)
	}
	for id := range in.Certificates {
		c := in.Certificates[id]
		if err := config.ValidateCertificateRenderSafety(&c); err != nil {
			return Rendered{}, fmt.Errorf("certificate %q is unsafe to render: %w", id, err)
		}
	}
	// The HTTP-01 helper address comes from the database, never from this
	// process's environment: easy-waf-api, easy-waf-acmed and easy-waf-admin all
	// reach this function, and a backend that disagreed with the listener would
	// leave HAProxy health-checking a closed port with no error anywhere.
	in.ACMEBackendAddr = config.ACMEInternalHTTPOrDefault(in.Settings.ACMEInternalHTTP)
	if in.ForwardAuthLuaPath == "" {
		in.ForwardAuthLuaPath = DefaultForwardAuthLuaPath
	}
	in.TrustedProxySrc = joinCIDRs(in.Settings.TrustedProxyCIDRs)
	in.ProxyProtocolSrc = joinCIDRs(in.Settings.ProxyProtocolCIDRs)
	in.RealIPFetch = fmt.Sprintf("req.hdr_ip(%s,-1)", config.RealIPHeaderOrDefault(in.Settings.RealIPHeader))

	in.UseCrowdSecFilter = strings.TrimSpace(in.Settings.SPOEConfigPath) != ""
	if in.UseCrowdSecFilter {
		in.UseCrowdSecFilter = false
		for i := range in.Applications {
			if !in.Applications[i].Enabled {
				continue
			}
			a := in.Applications[i]
			config.NormalizeApplicationSecurity(&a.Security)
			if a.Security.CrowdSecEnabled {
				in.UseCrowdSecFilter = true
				break
			}
		}
	}
	for i := range in.Applications {
		if _, err := profiles.Resolve(in.Applications[i].Profile); err != nil {
			return Rendered{}, err
		}
		// An unset policy on ha-mcp is the preset, including when the row was
		// written by a caller that did not go through the HTTP API.
		in.Applications[i].PathPolicy = profiles.ResolvePathPolicy(in.Applications[i].Profile, in.Applications[i].PathPolicy, nil)
		// Re-validate on every render, not just on write: these fields are
		// interpolated into config lines, so the generator must not depend on
		// the API handler having been the only way the row was stored.
		if err := config.ValidateApplicationRenderSafety(&in.Applications[i]); err != nil {
			return Rendered{}, fmt.Errorf("application %q is unsafe to render: %w", in.Applications[i].ID, err)
		}
	}
	if err := checkIdentifierCollisions(in.Applications); err != nil {
		return Rendered{}, err
	}
	apps := make([]AppRender, 0, len(in.Applications))
	for _, app := range in.Applications {
		if !app.Enabled {
			continue
		}
		config.NormalizeListenMode(&app)
		config.NormalizeApplicationSecurity(&app.Security)
		p, err := profiles.Resolve(app.Profile)
		if err != nil {
			return Rendered{}, err
		}
		tag := sanitizeAppACLTag(app.ID, app.PublicHost)
		geoPath := geoip.AppEnforceMapPath(in.StateDir, app.ID)
		useAppGeo := app.Security.GeoIPEnabled && geoip.UseEnforceMapInRender(true, geoPath)
		burst := p.RateLimitBurst
		if app.Security.RateLimitBurstOverride != nil {
			burst = *app.Security.RateLimitBurstOverride
		} else if app.Security.RateLimitRPSOverride != nil {
			burst = *app.Security.RateLimitRPSOverride * 2
		}
		if burst < 1 {
			burst = 1
		}
		servers := appServers(app)
		usesDNS := false
		for _, sv := range servers {
			usesDNS = usesDNS || sv.UsesDNS
		}
		maxBody, blockMultipart := p.BodyPolicy(app.Security)
		exposure, err := buildPathExposure(app, tag, in.StateDir)
		if err != nil {
			return Rendered{}, err
		}
		apps = append(apps, AppRender{
			Application:          app,
			Profile:              p,
			ACLTag:               tag,
			GeoEnforceMapPath:    geoPath,
			UsePerAppGeo:         useAppGeo,
			RateLimitBurst:       burst,
			BackendUsesDNS:       usesDNS,
			Servers:              servers,
			MaintenanceBypassSrc: joinCIDRs(app.MaintenanceBypassCIDRs),
			ForwardAuthBypassSrc: joinCIDRs(app.ForwardAuthBypassCIDRs),
			MaxBodyBytes:         maxBody,
			BlockMultipart:       blockMultipart,
			Exposure:             exposure,
		})
	}
	in.NeedsDNSResolver = false
	in.TCPServices = nil
	for _, t := range in.Settings.TCPServices {
		if !t.Enabled {
			continue
		}
		tr := TCPServiceRender{TCPService: t, AllowSrc: joinCIDRs(t.AllowCIDRs), UsesDNS: !backendHostIsLiteralIP(t.BackendHost)}
		in.NeedsDNSResolver = in.NeedsDNSResolver || tr.UsesDNS
		in.TCPServices = append(in.TCPServices, tr)
	}
	in.TLSPassthrough = nil
	for _, p := range in.Settings.TLSPassthrough {
		if !p.Enabled {
			continue
		}
		pr := TLSPassthroughRender{TLSPassthrough: p, AllowSrc: joinCIDRs(p.AllowCIDRs), UsesDNS: !backendHostIsLiteralIP(p.BackendHost)}
		if d, ok := strings.CutPrefix(p.ServerName, "*."); ok {
			pr.Backend, pr.Match = "ptw_"+sanitizeHAProxyIdent(d), "req_ssl_sni -m end -i ."+d
		} else {
			pr.Backend, pr.Match = "pt_"+sanitizeHAProxyIdent(p.ServerName), "req_ssl_sni -i "+p.ServerName
		}
		in.NeedsDNSResolver = in.NeedsDNSResolver || pr.UsesDNS
		in.TLSPassthrough = append(in.TLSPassthrough, pr)
	}
	for _, a := range apps {
		if a.BackendUsesDNS {
			in.NeedsDNSResolver = true
			break
		}
	}
	var httpsApps, httpApps, redirectApps []AppRender
	for _, a := range apps {
		switch a.Application.ListenMode {
		case "http_only":
			httpApps = append(httpApps, a)
		case "http_and_https":
			httpApps = append(httpApps, a)
			httpsApps = append(httpsApps, a)
		default: // https_only, redirect_to_https
			httpsApps = append(httpsApps, a)
			redirectApps = append(redirectApps, a)
		}
	}
	for _, p := range in.TLSPassthrough {
		for _, a := range httpsApps {
			if config.TLSPassthroughMatches(p.ServerName, a.Application.PublicHost) {
				return Rendered{}, fmt.Errorf("tls_passthrough %q also covers application %q, which is published on :443", p.ServerName, a.Application.PublicHost)
			}
		}
	}
	in.BackendApps = apps
	in.UseForwardAuth = false
	for _, a := range apps {
		if a.Application.ForwardAuthURL != "" {
			in.UseForwardAuth = true
		}
	}
	in.HTTPSApps = httpsApps
	in.HTTPApps = httpApps
	in.RedirectApps = redirectApps
	exempt := make([]string, 0, len(httpsApps))
	for _, a := range httpsApps {
		if a.Application.ListenMode == "http_and_https" {
			exempt = append(exempt, a.Application.PublicHost)
		}
	}
	in.HSTSExemptHosts = strings.Join(exempt, " ")
	in.HTTPClientTimeout = maxClientTimeout(httpApps)
	in.HTTPSClientTimeout = maxClientTimeout(httpsApps)

	crtLines := buildCRTList(in)
	in.HasHTTPSFrontend = len(httpsApps) > 0 && len(crtLines) > 0
	in.HTTPSChainSocket = ""
	if len(in.TLSPassthrough) > 0 && in.HasHTTPSFrontend {
		dir := filepath.Dir(in.Settings.HAProxyStatsSocketPath)
		if in.Settings.HAProxyStatsSocketPath == "" || dir == "." {
			dir = "/run/haproxy"
		}
		in.HTTPSChainSocket = filepath.Join(dir, "easy-waf-https.sock")
	}
	in.UseCrowdSecHTTP = false
	in.UseCrowdSecHTTPS = false
	if strings.TrimSpace(in.Settings.SPOEConfigPath) != "" {
		for _, a := range httpApps {
			if a.Application.Security.CrowdSecEnabled {
				in.UseCrowdSecHTTP = true
				break
			}
		}
		if in.HasHTTPSFrontend {
			for _, a := range httpsApps {
				if a.Application.Security.CrowdSecEnabled {
					in.UseCrowdSecHTTPS = true
					break
				}
			}
		}
	}
	in.UseCrowdSecFilter = in.UseCrowdSecHTTP || in.UseCrowdSecHTTPS

	var crtBuf strings.Builder
	for _, line := range crtLines {
		crtBuf.WriteString(line)
		crtBuf.WriteByte('\n')
	}

	var cfgBuf bytes.Buffer
	if err := compiledTemplate.Execute(&cfgBuf, in); err != nil {
		return Rendered{}, err
	}
	cfg := cfgBuf.String()
	sum := sha256.Sum256([]byte(cfg))
	return Rendered{
		HAProxyConfig: cfg,
		CRTList:       crtBuf.String(),
		SHA256:        hex.EncodeToString(sum[:]),
		RequiresTLS:   in.HasHTTPSFrontend,
	}, nil
}

func buildCRTList(in RenderInput) []string {
	lines := make([]string, 0, len(in.Applications))
	seen := map[string]struct{}{}
	for _, app := range in.Applications {
		if !app.Enabled || app.CertificateID == "" {
			continue
		}
		config.NormalizeListenMode(&app)
		c, ok := in.Certificates[app.CertificateID]
		if !ok {
			continue
		}
		bundle := c.BundlePath
		if bundle == "" && c.FullchainPath != "" && c.PEMKeyPath != "" {
			// Apply step should create bundle; render-time optional placeholder skipped
			continue
		}
		if bundle == "" {
			continue
		}
		if _, dup := seen[bundle]; dup {
			continue
		}
		seen[bundle] = struct{}{}
		lines = append(lines, fmt.Sprintf("%s alpn h2,http/1.1", bundle))
	}
	return lines
}

// sanitizeHAProxyIdent maps a name into the characters HAProxy accepts in proxy
// and ACL names. '-' is preserved (HAProxy allows it); everything outside
// [A-Za-z0-9_-], including '.', becomes '_'.
//
// Preserving '-' is a security fix, not cosmetics. This used to collapse '-'
// into '_' as well, which made the mapping non-injective over the application-ID
// charset ([A-Za-z0-9_-], see config.ValidateResourceID): "pay-api" and
// "pay_api" are two distinct rows that produced a single ACL tag, and HAProxy
// silently ORs same-named ACLs. One application's IP blacklist, GeoIP, WAF and
// routing rules then also applied to the other application's host, in whichever
// direction the first match happened to win.
//
// The host-derived fallback maps '.' to '_', which is injective only because
// config.validHostnameRe excludes '_' from public_host — it did not, once, and
// "a.b.com" and "a_b.com" both produced bk_a_b_com. checkIdentifierCollisions is
// the backstop if that ever slips again.
func sanitizeHAProxyIdent(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}

func sanitizeBackendName(host string) string {
	return "bk_" + sanitizeHAProxyIdent(host)
}

func sanitizeAppACLTag(id, publicHost string) string {
	s := strings.TrimSpace(id)
	if s == "" {
		s = publicHost
	}
	s = sanitizeHAProxyIdent(s)
	if strings.Trim(s, "_-") == "" {
		return "app"
	}
	return s
}

func formatHAProxyDuration(d time.Duration) string {
	if d <= 0 {
		return "1s"
	}
	s := int(d.Round(time.Second).Seconds())
	if s < 1 {
		s = 1
	}
	return fmt.Sprintf("%ds", s)
}

func methodSlug(m string) string {
	m = strings.TrimSpace(strings.ToUpper(m))
	m = strings.ReplaceAll(m, "-", "_")
	if m == "" {
		return "x"
	}
	return strings.ToLower(m)
}

// joinCIDRs joins non-empty trimmed CIDRs with spaces for HAProxy "acl name src a b c".
func joinCIDRs(cidrs []string) string {
	var b strings.Builder
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(c)
	}
	return b.String()
}

// haproxyTemplate targets HAProxy 2.8, the Ubuntu 24.04 series, and is checked with `haproxy -c`.
const haproxyTemplate = `{{/* Easy Home WAF — generated; do not edit by hand */}}
global
	log stdout format raw local0
	maxconn 50000
{{- if .UseForwardAuth}}
	lua-load {{.ForwardAuthLuaPath}}
{{- end}}
	# The stock haproxy.service starts as root; drop it after binding.
	user haproxy
	group haproxy
	stats socket {{.Settings.HAProxyStatsSocketPath}} mode 660 level admin
	stats timeout 30s
	# pidfile omitted: systemd supplies -p /run/haproxy/haproxy.pid (see haproxy.service.d drop-in).
	# Mozilla "intermediate" without DHE: TLS 1.2 with ECDHE AEAD suites, and TLS 1.3.
	ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
	ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
	ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	dontlognull
	option	httplog
	option	http-server-close
	option	forwardfor except 127.0.0.0/8
	timeout connect 5s
	timeout client  50s
	timeout server  50s
	timeout tunnel  3600s
	# Bodies of the responses HAProxy makes itself: denials, no server, timeouts.
{{errorPages}}

{{if .NeedsDNSResolver}}
# System DNS (split-DNS / internal forwarders via /etc/resolv.conf)
resolvers easy_waf_dns
	parse-resolv-conf
	resolve_retries 3
	timeout resolve 2s
	timeout retry 2s
	hold valid 30s
	hold nx 5s

{{end}}
# HTTP — ACME HTTP-01, per-app plain HTTP, per-host HTTPS redirects, default redirect
# Rule order: ACLs → all http-request → use_backend (avoids HAProxy 3.x "http-request after use_backend" warnings).
frontend fe_http
	bind *:80
{{- if .Settings.ListenIPv6}}
	bind :::80 v6only
{{- end}}
	mode http
{{- template "realIP" .}}
{{- template "securityHeaders" .}}
{{- template "blockCapture"}}
{{if .HTTPClientTimeout}}	# HAProxy 2.8 cannot change timeout client per request. This is the longest any app on this frontend asked for.
	# timeout http-request still aborts an incomplete request, which the client timeout does not.
	timeout client {{.HTTPClientTimeout}}s
	timeout http-request 10s
{{end}}	acl acme path_beg /.well-known/acme-challenge/
{{range $a := .HTTPApps}}
	# HTTP app: {{$a.Application.Name}} ({{$a.Application.PublicHost}})
	acl http_app_{{$a.ACLTag}}_host hdr(host) -i {{$a.Application.PublicHost}}
{{end}}
{{- if .RedirectApps}}
	acl redir_fe_any_host hdr(host) -i {{range $i, $a := .RedirectApps}}{{if $i}} {{end}}{{$a.Application.PublicHost}}{{end}}
{{- end}}
{{- if and .HasHTTPSFrontend .HTTPApps}}
	acl fe_http_keeps_plain hdr(host) -i {{range $i, $a := .HTTPApps}}{{if $i}} {{end}}{{$a.Application.PublicHost}}{{end}}
{{- end}}
{{if .UseCrowdSecHTTP}}
	# CrowdSec SPOE — engine id must match the [section] in {{.Settings.SPOEConfigPath}}.
	# The bouncer's messages send unique-id, so the frontend must define one.
	unique-id-format %[uuid()]
	filter spoe engine {{.Settings.CrowdSecEngineName}} config {{.Settings.SPOEConfigPath}}
{{end}}
{{- if .RedirectApps}}
	http-request redirect scheme https code 301 if redir_fe_any_host !acme
{{- end}}
{{- if and .HasHTTPSFrontend .HTTPApps}}
	http-request redirect scheme https code 301 if !acme !fe_http_keeps_plain
{{- else if .HasHTTPSFrontend}}
	http-request redirect scheme https code 301 if !acme
{{- end}}
{{- if .HTTPApps}}
	# Universal blocks (plain HTTP vhosts; ACME excluded)
	acl p_http_git     path_beg /.git
	acl p_http_env     path_beg /.env
	http-request capture str(sensitive_path) id 1 if p_http_git !acme
	http-request deny deny_status 403 if p_http_git !acme
	http-request capture str(sensitive_path) id 1 if p_http_env !acme
	http-request deny deny_status 403 if p_http_env !acme
	acl http_bad_method method TRACE CONNECT
	http-request capture str(method) id 1 if http_bad_method !acme
	http-request deny deny_status 405 if http_bad_method !acme
{{- end}}
{{range $a := .HTTPApps}}
{{template "appSecurity" (appSec $ $a (printf "http_app_%s_host" $a.ACLTag) true)}}
{{end}}
	use_backend bk_acme if acme
{{range $a := .HTTPApps}}
	use_backend {{backendName $a.Application.PublicHost}} if http_app_{{$a.ACLTag}}_host
{{end}}
{{- if not .HasHTTPSFrontend}}
	default_backend bk_http_default
{{- end}}

# ACME challenges: easy-waf-api loopback serves Lego webroot (setting acme_internal_http, default 127.0.0.1:8089)
backend bk_acme
	mode http
	server acme {{.ACMEBackendAddr}} check
{{- if .UseCrowdSecFilter}}

# CrowdSec SPOA bouncer. The name is fixed by use-backend in the vendor's SPOE file;
# the installer binds the bouncer to this loopback address.
backend crowdsec-spoa
	mode tcp
	timeout connect 2s
	timeout server 60s
	server spoa 127.0.0.1:9000
{{- end}}
{{if not .HasHTTPSFrontend}}

# :80 catch-all when there is no fe_https (plain HTTP edge only)
backend bk_http_default
	mode http
	http-request deny deny_status 404
{{end}}

{{if .HasHTTPSFrontend}}
# HTTPS edge — one bind, many PEMs in crt-list → SNI picks cert; Host header routes to backends (single WAN IP).
frontend fe_https
{{- if .HTTPSChainSocket}}
	# Reached through fe_tls_in (TLS passthrough); PROXY v2 on that hop keeps the client address.
	bind unix@{{.HTTPSChainSocket}} mode 600 user haproxy accept-proxy ssl crt-list {{.CRTListPath}} alpn h2,http/1.1
{{- else}}
	bind *:443 ssl crt-list {{.CRTListPath}} alpn h2,http/1.1
{{- if .Settings.ListenIPv6}}
	bind :::443 v6only ssl crt-list {{.CRTListPath}} alpn h2,http/1.1
{{- end}}
{{- end}}
	mode http
{{- if .HTTPSChainSocket}}
{{- template "realIPHeader" .}}
{{- else}}
{{- template "realIP" .}}
{{- end}}
{{- template "securityHeaders" .}}
{{- template "blockCapture"}}
{{if .HTTPSClientTimeout}}	# HAProxy 2.8 cannot change timeout client per request. This is the longest any app on this frontend asked for.
	# timeout http-request still aborts an incomplete request, which the client timeout does not.
	timeout client {{.HTTPSClientTimeout}}s
	timeout http-request 10s
{{end}}	option forwardfor
{{if $.UseCrowdSecHTTPS}}
	# CrowdSec SPOE — engine id must match the [section] in {{.Settings.SPOEConfigPath}}.
	# The bouncer's messages send unique-id, so the frontend must define one.
	unique-id-format %[uuid()]
	filter spoe engine {{.Settings.CrowdSecEngineName}} config {{.Settings.SPOEConfigPath}}
{{end}}
	http-request set-header X-Forwarded-Proto https
{{- if .HSTSExemptHosts}}
	acl hsts_exempt hdr(host) -i {{.HSTSExemptHosts}}
	http-response set-header Strict-Transport-Security "max-age=15552000{{if .Settings.HSTSIncludeSubdomains}}; includeSubDomains{{end}}" if { ssl_fc } !hsts_exempt
{{- else}}
	http-response set-header Strict-Transport-Security "max-age=15552000{{if .Settings.HSTSIncludeSubdomains}}; includeSubDomains{{end}}" if { ssl_fc }
{{- end}}
	# Universal blocks (all vhosts)
	acl p_git     path_beg /.git
	acl p_env     path_beg /.env
	http-request capture str(sensitive_path) id 1 if p_git || p_env
	http-request deny deny_status 403 if p_git || p_env
	acl bad_method method TRACE CONNECT
	http-request capture str(method) id 1 if bad_method
	http-request deny deny_status 405 if bad_method
{{range $i, $a := .HTTPSApps}}
	acl app_{{$a.ACLTag}}_host hdr(host) -i {{$a.Application.PublicHost}}
{{template "appSecurity" (appSec $ $a (printf "app_%s_host" $a.ACLTag) false)}}
{{end}}
{{range $a := .HTTPSApps}}
	use_backend {{backendName $a.Application.PublicHost}} if app_{{$a.ACLTag}}_host
{{end}}
	default_backend bk_not_found

backend bk_not_found
	mode http
	http-request deny deny_status 404
{{end}}

{{if .TLSPassthrough}}
# :443 entry for TLS passthrough: listed server names reach their backends still encrypted{{if .HasHTTPSFrontend}}, the rest goes to fe_https{{end}}.
frontend fe_tls_in
	mode tcp
	option tcplog
	option dontlog-normal
	no option http-server-close
	bind *:443
{{- if .Settings.ListenIPv6}}
	bind :::443 v6only
{{- end}}
{{- template "proxyProtocol" .}}
	timeout client 1h
	tcp-request inspect-delay 5s
	tcp-request content accept if { req_ssl_hello_type 1 }
{{- range $p := .TLSPassthrough}}
	use_backend {{$p.Backend}} if { {{$p.Match}} }
{{- end}}
	default_backend {{if .HasHTTPSFrontend}}bk_tls_https{{else}}bk_tls_none{{end}}
{{if .HasHTTPSFrontend}}
backend bk_tls_https
	mode tcp
	no option http-server-close
	timeout server 1h
	server fe_https unix@{{.HTTPSChainSocket}} send-proxy-v2
{{else}}
backend bk_tls_none
	mode tcp
	tcp-request content reject
{{end}}
{{- range $p := .TLSPassthrough}}
# TLS passthrough {{$p.ServerName}}: not decrypted, no HTTP rules apply.
backend {{$p.Backend}}
	mode tcp
	no option http-server-close
	timeout server 1h
{{- if $p.AllowSrc}}
	tcp-request content reject if !{ src {{$p.AllowSrc}} }
{{- end}}
{{- if $.UseIPBlacklist}}
	tcp-request content reject if { src -f {{$.IPBlacklistMapPath}} }
{{- end}}
	server s1 {{$p.BackendHost}}:{{$p.BackendPort}}{{if $p.UsesDNS}} resolvers easy_waf_dns init-addr last,libc,none{{end}}{{if $p.SendProxy}} send-proxy-v2 check-send-proxy{{end}} check inter 5s fall 3 rise 2
{{end}}
{{end -}}
{{range $t := .TCPServices}}
# TCP service {{$t.Name}}: raw TCP, no HTTP rules apply.
frontend tcp_{{$t.Name}}
	mode tcp
	option tcplog
	no option http-server-close
	bind *:{{$t.ListenPort}}
{{- if $.Settings.ListenIPv6}}
	bind :::{{$t.ListenPort}} v6only
{{- end}}
{{- if $t.AllowSrc}}
	tcp-request connection reject if !{ src {{$t.AllowSrc}} }
{{- end}}
{{- if $.UseIPBlacklist}}
	tcp-request connection reject if { src -f {{$.IPBlacklistMapPath}} }
{{- end}}
	timeout client 1h
	default_backend tcpbk_{{$t.Name}}

backend tcpbk_{{$t.Name}}
	mode tcp
	no option http-server-close
	timeout server 1h
	server s1 {{$t.BackendHost}}:{{$t.BackendPort}}{{if $t.UsesDNS}} resolvers easy_waf_dns init-addr last,libc,none{{end}} check inter 5s fall 3 rise 2
{{end -}}
{{range $i, $a := .BackendApps}}
{{range $r := $a.Exposure.Rates}}backend {{$r.Stick}}
	stick-table type ip size 50k expire 5m store http_req_rate(10s)
{{end -}}
backend {{backendName $a.Application.PublicHost}}
	mode http
	timeout connect {{haDur $a.Profile.ConnectTimeout}}
	timeout server {{haDur $a.Profile.ServerTimeout}}
	{{- if $a.Profile.HTTPKeepAlive }}
	option http-keep-alive
	{{- else }}
	option http-server-close
	{{- end }}
	{{- if $a.Application.Maintenance }}
	# Maintenance mode: a 503 page without reaching the servers{{if $a.MaintenanceBypassSrc}}, except from the bypass sources{{end}}.
	http-request return status 503 content-type "text/html; charset=utf-8" hdr Retry-After 600 hdr Cache-Control no-store string "{{maintenancePage}}"{{if $a.MaintenanceBypassSrc}} if !{ src {{$a.MaintenanceBypassSrc}} }{{end}}
	{{- end }}
{{- if $a.Application.Security.RateLimitEnabled}}
	stick-table type ip size 200k expire 5m store http_req_rate(10s)
	http-request track-sc0 src
	acl rl_abuse_{{$i}} sc0_http_req_rate gt {{$a.RateLimitBurst}}
{{- if and $.UseIPAllowlist $a.Application.Security.IPAllowlistEnabled}}
	acl be_ipwl_white_{{$i}} src -f {{$.IPAllowlistMapPath}}
	http-request deny deny_status 429 if rl_abuse_{{$i}} !be_ipwl_white_{{$i}}
{{- else}}
	http-request deny deny_status 429 if rl_abuse_{{$i}}
{{- end}}
{{- end}}
{{- if $a.Application.ForwardAuthURL}}
	# Forward auth, fail closed: only a 2xx answer from the auth service reaches the servers{{if $a.ForwardAuthBypassSrc}}; the bypass sources skip it{{end}}.
	http-request del-header Remote-User
	http-request del-header Remote-Groups
	http-request del-header Remote-Email
	http-request del-header Remote-Name
	http-request lua.easywaf_auth "{{$a.Application.ForwardAuthURL}}"{{if $a.ForwardAuthBypassSrc}} if !{ src {{$a.ForwardAuthBypassSrc}} }{{end}}
	http-request redirect location %[var(txn.auth_location)] code 302 if !{ var(txn.auth_ok) -m bool } { var(txn.auth_location) -m found }{{if $a.ForwardAuthBypassSrc}} !{ src {{$a.ForwardAuthBypassSrc}} }{{end}}
	http-request deny deny_status 401 if !{ var(txn.auth_ok) -m bool }{{if $a.ForwardAuthBypassSrc}} !{ src {{$a.ForwardAuthBypassSrc}} }{{end}}
	http-request set-header Remote-User %[var(txn.auth_remote_user)] if { var(txn.auth_remote_user) -m found }
	http-request set-header Remote-Groups %[var(txn.auth_remote_groups)] if { var(txn.auth_remote_groups) -m found }
	http-request set-header Remote-Email %[var(txn.auth_remote_email)] if { var(txn.auth_remote_email) -m found }
	http-request set-header Remote-Name %[var(txn.auth_remote_name)] if { var(txn.auth_remote_name) -m found }
{{- end}}{{if $a.Exposure.AppServer}}
	http-request set-timeout server {{$a.Exposure.AppServer}}s{{end}}{{range $p := $a.Exposure.BackPaths}}
	acl {{$p.Name}} path -m str {{$p.Exact}}
	acl {{$p.Name}} path_beg {{$p.Dir}}{{end}}{{range $t := $a.Exposure.Timeouts}}
	http-request set-timeout server {{$t.Server}}s if {{$t.PathName}}{{end}}{{range $r := $a.Exposure.Rates}}
	http-request track-sc1 src table {{$r.Stick}} if {{$r.PathName}}{{if $r.Unless}} {{$r.Unless}}{{end}}
	http-request deny deny_status 429 if {{$r.PathName}}{{if $r.Unless}} {{$r.Unless}}{{end}} { sc1_http_req_rate({{$r.Stick}}) gt {{$r.Limit}} }{{end}}{{range $h := $a.Exposure.Strip}}
	# Removed before the backend sees the request. Not captured in httplog.
	http-request del-header {{$h}}{{end}}
	{{- if $a.Application.WebSocket }}
	timeout tunnel 3600s
	{{- end }}
	{{- if $a.Application.HealthPath }}
	option httpchk GET {{$a.Application.HealthPath}}
	{{- end }}
	{{- if $a.Application.BackendBalance }}
	balance {{$a.Application.BackendBalance}}
	{{- end }}
	{{- range $s := $a.Servers }}
	server {{$s.Name}} {{$s.Host}}:{{$s.Port}}{{$s.TLS}}{{if $s.UsesDNS}} resolvers easy_waf_dns init-addr last,libc,none{{end}} check inter 3s fall 3 rise 2{{if $s.Backup}} backup{{end}}
	{{- end }}
{{end}}
{{define "realIP"}}
{{- template "proxyProtocol" .}}
{{- template "realIPHeader" .}}
{{- end}}
{{- define "proxyProtocol"}}
{{- if .ProxyProtocolSrc}}
	# PROXY protocol is required from these sources only; others connect directly.
	tcp-request connection expect-proxy layer4 if { src {{.ProxyProtocolSrc}} }
{{- end}}
{{- end}}
{{- define "realIPHeader"}}
{{- if .TrustedProxySrc}}
	# Before any rule that reads src: IP lists, GeoIP, CrowdSec, rate limits and logs see the client.
	http-request set-src {{.RealIPFetch}} if { src {{.TrustedProxySrc}} } { {{.RealIPFetch}} -m found }
{{- end}}
{{- end}}
{{- define "securityHeaders"}}
{{- if .Settings.SecurityHeadersEnabled}}
	# Added only when the backend did not send them; version banners are removed.
	http-response set-header X-Content-Type-Options nosniff unless { res.hdr(X-Content-Type-Options) -m found }
	http-response set-header Referrer-Policy strict-origin-when-cross-origin unless { res.hdr(Referrer-Policy) -m found }
	http-response del-header Server
	http-response del-header X-Powered-By
{{- end}}
{{- end}}
{{- define "blockCapture"}}
	# httplog shows {host|rule}: the rule that refused a request (Logs → Blocked requests).
	declare capture request len 64
	declare capture request len 24
	http-request capture req.hdr(host) id 0
{{- end}}
{{- define "appSecurity"}}
{{- $root := .Root -}}
{{- $a := .App -}}
{{- $host := .HostACL -}}
{{- $acme := acmeSuffix .SkipACME -}}
	# === Application: {{$a.Application.Name}} ({{$a.Application.PublicHost}}) ===
{{- if $a.Exposure.Allowlist}}
	# Allowlist is evaluated before the IP allow shortcut, so a trusted source still cannot reach other paths.
	acl app_{{$a.ACLTag}}_allow path -m str {{$a.Exposure.AllowExact}}
	acl app_{{$a.ACLTag}}_allow path_beg {{$a.Exposure.AllowDirs}}
	http-request capture str(path_allowlist) id 1 if {{$host}} !app_{{$a.ACLTag}}_allow{{$acme}}
	http-request deny deny_status 404 if {{$host}} !app_{{$a.ACLTag}}_allow{{$acme}}
{{end}}{{range $p := $a.Exposure.FrontPaths}}
	acl {{$p.Name}} path -m str {{$p.Exact}}
	acl {{$p.Name}} path_beg {{$p.Dir}}
{{end}}{{range $h := $a.Exposure.Headers}}
{{if eq $h.Mode "found"}}	acl {{$h.CheckName}} req.hdr({{$h.Header}}) -m found
{{else if eq $h.Mode "prefix"}}	acl {{$h.CheckName}} req.hdr({{$h.Header}}) -m beg "{{$h.Prefix}}"
{{else if eq $h.Mode "file"}}	acl {{$h.CheckName}} req.hdr({{$h.Header}}) -m str -f {{$h.File}}
{{end}}	# httplog stays on the request line; this header is not captured.
	http-request capture str(path_header) id 1 if {{$host}} {{$h.PathName}} !{{$h.CheckName}}{{$acme}}
	http-request deny deny_status 401 if {{$host}} {{$h.PathName}} !{{$h.CheckName}}{{$acme}}
{{end}}{{- if and $root.UseIPAllowlist $a.Application.Security.IPAllowlistEnabled}}
	acl app_{{$a.ACLTag}}_white src -f {{$root.IPAllowlistMapPath}}
	http-request allow if {{$host}} app_{{$a.ACLTag}}_white{{$acme}}
{{- end}}
{{- if and $root.UseIPBlacklist $a.Application.Security.IPBlacklistEnabled}}
	acl app_{{$a.ACLTag}}_black src -f {{$root.IPBlacklistMapPath}}
	http-request capture str(ip_blacklist) id 1 if {{$host}} app_{{$a.ACLTag}}_black{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_black{{$acme}}
{{- end}}
{{- if $a.UsePerAppGeo}}
	acl app_{{$a.ACLTag}}_geo src -f {{$a.GeoEnforceMapPath}}
{{- if eq $a.Application.Security.GeoIPPolicy "deny"}}
	http-request capture str(geoip) id 1 if {{$host}} app_{{$a.ACLTag}}_geo{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_geo{{$acme}}
{{- else}}
	http-request capture str(geoip) id 1 if {{$host}} !app_{{$a.ACLTag}}_geo{{$acme}}
	http-request deny deny_status 403 if {{$host}} !app_{{$a.ACLTag}}_geo{{$acme}}
{{- end}}
{{- end}}
{{- if and $root.Settings.BlockEmptyUA $a.Application.Security.BotProtectionEnabled}}
	acl app_{{$a.ACLTag}}_empty_ua req.hdr(User-Agent) -m len 0
	http-request capture str(empty_ua) id 1 if {{$host}} app_{{$a.ACLTag}}_empty_ua{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_empty_ua{{$acme}}
{{- end}}
{{- if and $root.UseBlockedUserAgents $a.Application.Security.BotProtectionEnabled}}
	acl app_{{$a.ACLTag}}_bad_ua req.hdr(User-Agent) -m sub -i -f {{$root.BlockedUserAgentsMapPath}}
	http-request capture str(bad_ua) id 1 if {{$host}} app_{{$a.ACLTag}}_bad_ua{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_bad_ua{{$acme}}
{{- end}}
{{- if $a.Application.Security.BasicWAFEnabled}}
	acl app_{{$a.ACLTag}}_sqli query -m reg -i (union\s+select|insert\s+into|drop\s+table|delete\s+from|update[^;]*set|;.*--)
	acl app_{{$a.ACLTag}}_sqli_path path -m reg -i (union\s+select|insert\s+into|drop\s+table|\.\./\.\.)
	acl app_{{$a.ACLTag}}_xss query -m reg -i (<script|javascript:|on(error|load|click|mouse)\s*=)
	acl app_{{$a.ACLTag}}_xss_path path -m reg -i (<script|javascript:)
	acl app_{{$a.ACLTag}}_traversal path -m reg -i \.\./
	http-request capture str(sqli) id 1 if {{$host}} app_{{$a.ACLTag}}_sqli{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_sqli{{$acme}}
	http-request capture str(sqli) id 1 if {{$host}} app_{{$a.ACLTag}}_sqli_path{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_sqli_path{{$acme}}
	http-request capture str(xss) id 1 if {{$host}} app_{{$a.ACLTag}}_xss{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_xss{{$acme}}
	http-request capture str(xss) id 1 if {{$host}} app_{{$a.ACLTag}}_xss_path{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_xss_path{{$acme}}
	http-request capture str(traversal) id 1 if {{$host}} app_{{$a.ACLTag}}_traversal{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_traversal{{$acme}}
{{- end}}
{{- if $a.Application.Security.MethodFilterEnabled}}
{{- range $k, $m := $a.Profile.ExtraBlockedMethods}}
	acl app_{{$a.ACLTag}}_bm_{{$k}}_{{methodSlug $m}} method {{$m}}
	http-request capture str(method) id 1 if {{$host}} app_{{$a.ACLTag}}_bm_{{$k}}_{{methodSlug $m}}{{$acme}}
	http-request deny deny_status 405 if {{$host}} app_{{$a.ACLTag}}_bm_{{$k}}_{{methodSlug $m}}{{$acme}}
{{- end}}
{{- end}}
{{- if $a.Application.Security.PathACLEnabled}}
{{- range $j, $p := $a.Profile.BlockPaths}}
	http-request capture str(blocked_path) id 1 if {{$host}}{{$acme}} { path_beg {{$p}} }
	http-request deny deny_status 403 if {{$host}}{{$acme}} { path_beg {{$p}} }
{{- end}}
{{- end}}
{{- range $ri, $rp := $a.Application.RestrictedPaths}}
{{- $rpCidr := joinCIDRs $rp.AllowedCIDRs}}
{{- if and $rp.PathPrefix $rpCidr}}
	# Per-app restricted path: {{$a.Application.Name}} {{$rp.PathPrefix}}
	acl app_{{$a.ACLTag}}_rp_{{$ri}}_path path_beg {{$rp.PathPrefix}}
	acl app_{{$a.ACLTag}}_rp_{{$ri}}_net src {{$rpCidr}}
	http-request capture str(restricted_path) id 1 if {{$host}} app_{{$a.ACLTag}}_rp_{{$ri}}_path !app_{{$a.ACLTag}}_rp_{{$ri}}_net{{$acme}}
	http-request deny deny_status 403 if {{$host}} app_{{$a.ACLTag}}_rp_{{$ri}}_path !app_{{$a.ACLTag}}_rp_{{$ri}}_net{{$acme}}
{{- end}}
{{- end}}
{{- if $a.BlockMultipart}}
	# Headers only: bodies are not inspected. req.hdr sees every value of a repeated
	# or comma-joined Content-Type. Status via return: deny_status has no 411 or 415.
	acl app_{{$a.ACLTag}}_multipart req.hdr(content-type) -m beg -i multipart/
{{- if $a.Application.Security.MultipartAllowedPaths}}
	acl app_{{$a.ACLTag}}_mp_allowed path -m str {{exactPaths $a.Application.Security.MultipartAllowedPaths}}
	acl app_{{$a.ACLTag}}_mp_allowed path_beg {{dirPrefixes $a.Application.Security.MultipartAllowedPaths}}
	acl app_{{$a.ACLTag}}_mp_dots path -m reg -i (\.|%2e){2}
	http-request capture str(multipart) id 1 if {{$host}} app_{{$a.ACLTag}}_multipart !app_{{$a.ACLTag}}_mp_allowed{{$acme}}
	http-request return status 415 content-type text/plain string "multipart requests are blocked on this path" if {{$host}} app_{{$a.ACLTag}}_multipart !app_{{$a.ACLTag}}_mp_allowed{{$acme}}
	http-request capture str(multipart) id 1 if {{$host}} app_{{$a.ACLTag}}_multipart app_{{$a.ACLTag}}_mp_dots{{$acme}}
	http-request return status 415 content-type text/plain string "multipart requests are blocked on this path" if {{$host}} app_{{$a.ACLTag}}_multipart app_{{$a.ACLTag}}_mp_dots{{$acme}}
{{- else}}
	http-request capture str(multipart) id 1 if {{$host}} app_{{$a.ACLTag}}_multipart{{$acme}}
	http-request return status 415 content-type text/plain string "multipart requests are blocked on this path" if {{$host}} app_{{$a.ACLTag}}_multipart{{$acme}}
{{- end}}
{{- end}}
{{- if $a.MaxBodyBytes}}
	# HAProxy cannot count a streamed body, so one of undeclared length is refused.
	acl app_{{$a.ACLTag}}_body_method method POST PUT PATCH
	http-request capture str(body_size) id 1 if {{$host}} { req.hdr_val(content-length) gt {{$a.MaxBodyBytes}} }{{$acme}}
	http-request return status 413 content-type text/plain string "request body too large" if {{$host}} { req.hdr_val(content-length) gt {{$a.MaxBodyBytes}} }{{$acme}}
	http-request capture str(content_length) id 1 if {{$host}} { req.fhdr(transfer-encoding) -m found }{{$acme}}
	http-request return status 411 content-type text/plain string "Content-Length required" if {{$host}} { req.fhdr(transfer-encoding) -m found }{{$acme}}
	http-request capture str(content_length) id 1 if {{$host}} app_{{$a.ACLTag}}_body_method !{ req.hdr(content-length) -m found }{{$acme}}
	http-request return status 411 content-type text/plain string "Content-Length required" if {{$host}} app_{{$a.ACLTag}}_body_method !{ req.hdr(content-length) -m found }{{$acme}}
{{- end}}
{{- if and $root.UseCrowdSecFilter $a.Application.Security.CrowdSecEnabled}}
	# No body group: nothing here inspects bodies, so no request is buffered for it.
	# The bouncer answers in txn.crowdsec.remediation; without this deny its decisions do nothing.
	# When it cannot be reached the variable stays unset and traffic passes (fail open).
	http-request send-spoe-group {{$root.Settings.CrowdSecEngineName}} crowdsec-http-no-body if {{$host}}{{$acme}}
	http-request capture str(crowdsec) id 1 if {{$host}}{{$acme}} { var(txn.crowdsec.remediation) -m found } !{ var(txn.crowdsec.remediation) -m str allow }
	# A page rather than a bare 403: the visitor learns why and what to send the owner.
	http-request return status 403 content-type "text/html; charset=utf-8" hdr Cache-Control no-store lf-string "<!doctype html><title>Access denied</title><h1>Access denied</h1><p>Your address %[src] is blocked on this site by CrowdSec, a shared reputation service. If this is a mistake, send this address to the site owner.</p>" if {{$host}}{{$acme}} { var(txn.crowdsec.remediation) -m found } !{ var(txn.crowdsec.remediation) -m str allow }
{{- end}}
{{end}}
`

var compiledTemplate = template.Must(template.New("haproxy").Funcs(template.FuncMap{
	"errorPages":      errorPages,
	"maintenancePage": maintenancePage,
	"backendName":     sanitizeBackendName,
	"join":            strings.Join,
	"exactPaths":      exactPaths,
	"dirPrefixes":     dirPrefixes,
	"joinCIDRs":       joinCIDRs,
	"haDur":           formatHAProxyDuration,
	"methodSlug":      methodSlug,
	"appSec":          appSec,
	"acmeSuffix":      acmeSuffix,
}).Parse(haproxyTemplate))

// Paths under stateDir for generated artifacts.
func Paths(stateDir string) (haproxyDir, cfgPath, crtListPath string) {
	haproxyDir = filepath.Join(stateDir, "haproxy")
	cfgPath = filepath.Join(haproxyDir, "haproxy.cfg")
	crtListPath = filepath.Join(haproxyDir, "crt-list.txt")
	return
}

// LiveCfgPath returns the filesystem path for the active HAProxy config.
// When settingsHAProxyConfigPath is non-empty it is returned cleaned; otherwise
// the default under stateDir (same as Paths) is used. Engine.Apply must write
// here so reload picks up the same file referenced in GlobalSettings.
func LiveCfgPath(stateDir, settingsHAProxyConfigPath string) string {
	if p := strings.TrimSpace(settingsHAProxyConfigPath); p != "" {
		return filepath.Clean(p)
	}
	_, cfg, _ := Paths(stateDir)
	return cfg
}

// checkIdentifierCollisions refuses to render when two enabled applications map
// onto one HAProxy identifier.
//
// The value of this is the error message. HAProxy rejects a duplicate proxy
// name, so a collision already stopped the apply — but with a message about
// `bk_a_b_com` rather than about the two rows that produced it, and every
// subsequent apply, including auto-apply, stayed wedged until somebody worked
// out which row to delete. Naming both applications turns a mystery into a
// two-minute fix.
//
// The public-host validator now rules out the ways a collision was reachable
// (uppercase, and '_'), so this is a backstop for whatever the next one is.
func checkIdentifierCollisions(apps []config.Application) error {
	type owner struct{ id, host string }
	backends := map[string]owner{}
	tags := map[string]owner{}
	for _, app := range apps {
		if !app.Enabled {
			continue
		}
		if name := sanitizeBackendName(app.PublicHost); name != "" {
			if prev, dup := backends[name]; dup {
				return fmt.Errorf("applications %q (%s) and %q (%s) both render as backend %s — "+
					"HAProxy rejects duplicate proxy names, so nothing can be applied until one of them changes",
					prev.id, prev.host, app.ID, app.PublicHost, name)
			}
			backends[name] = owner{app.ID, app.PublicHost}
		}
		if tag := sanitizeAppACLTag(app.ID, app.PublicHost); tag != "" {
			if prev, dup := tags[tag]; dup {
				return fmt.Errorf("applications %q (%s) and %q (%s) both render as ACL tag %s — "+
					"HAProxy silently ORs same-named ACLs, so one application's rules would also apply to the other's traffic",
					prev.id, prev.host, app.ID, app.PublicHost, tag)
			}
			tags[tag] = owner{app.ID, app.PublicHost}
		}
	}
	return nil
}
