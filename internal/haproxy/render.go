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
}

// RenderInput is passed to the HAProxy template.
type RenderInput struct {
	Settings                 config.GlobalSettings
	Applications             []config.Application
	BackendApps              []AppRender                   `json:"-"` // every enabled app (backend definitions)
	HTTPSApps                []AppRender                   `json:"-"` // fe_https: TLS edge (https_only, redirect_to_https, http_and_https)
	HTTPApps                 []AppRender                   `json:"-"` // fe_http: plain routing (http_only, http_and_https)
	RedirectApps             []AppRender                   `json:"-"` // fe_http: per-host redirect to HTTPS
	HasHTTPSFrontend         bool                          `json:"-"` // false when no :443 TLS vhosts (crt-list may still list unused PEMs)
	Certificates             map[string]config.Certificate // id -> cert
	CRTListPath              string                        // absolute path to generated crt-list file on disk
	IPBlacklistMapPath       string
	IPAllowlistMapPath       string
	UseIPBlacklist           bool
	UseIPAllowlist           bool
	BlockedUserAgentsMapPath string // absolute path to generated substring map (-m sub -f)
	UseBlockedUserAgents     bool   // enabled in settings and map has at least one pattern line
	StateDir                 string // state directory for per-app GeoIP map paths
	UseCrowdSecFilter        bool   // at least one app requests CrowdSec and SPOE path is configured
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
	}
	var apps []AppRender
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
		apps = append(apps, AppRender{
			Application:       app,
			Profile:           p,
			ACLTag:            tag,
			GeoEnforceMapPath: geoPath,
			UsePerAppGeo:      useAppGeo,
			RateLimitBurst:    burst,
		})
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
	in.BackendApps = apps
	in.HTTPSApps = httpsApps
	in.HTTPApps = httpApps
	in.RedirectApps = redirectApps

	crtLines := buildCRTList(in)
	in.HasHTTPSFrontend = len(httpsApps) > 0 && len(crtLines) > 0
	if !in.HasHTTPSFrontend {
		in.UseCrowdSecFilter = false
	}

	tmpl, err := template.New("haproxy").Funcs(template.FuncMap{
		"backendName": sanitizeBackendName,
		"join":        strings.Join,
		"joinCIDRs":   joinCIDRs,
		"haDur":       formatHAProxyDuration,
		"methodSlug":  methodSlug,
	}).Parse(haproxyTemplate)
	if err != nil {
		return Rendered{}, err
	}

	var crtBuf strings.Builder
	for _, line := range crtLines {
		crtBuf.WriteString(line)
		crtBuf.WriteByte('\n')
	}

	var cfgBuf bytes.Buffer
	data := struct {
		RenderInput
	}{
		RenderInput: in,
	}
	if err := tmpl.Execute(&cfgBuf, data); err != nil {
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
	var lines []string
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

func sanitizeBackendName(host string) string {
	h := strings.ReplaceAll(host, ".", "_")
	h = strings.ReplaceAll(h, "-", "_")
	return "bk_" + h
}

func sanitizeAppACLTag(id, publicHost string) string {
	s := strings.TrimSpace(id)
	if s == "" {
		s = strings.TrimPrefix(sanitizeBackendName(publicHost), "bk_")
	}
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
	if strings.Trim(s, "_") == "" {
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

// haproxyTemplate follows HAProxy 3.x syntax; validate with `haproxy -c`.
const haproxyTemplate = `{{/* Easy Home WAF — generated; do not edit by hand */}}
global
	log stdout format raw local0
	maxconn 50000
	stats socket {{.Settings.HAProxyStatsSocketPath}} mode 660 level admin
	stats timeout 30s
	pidfile /run/haproxy.pid

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

# HTTP — ACME HTTP-01, per-app plain HTTP, per-host HTTPS redirects, default redirect
# Rule order: all ACLs and http-request rules first, then use_backend (avoids HAProxy 3.0.x -c warnings / non-zero exit).
frontend fe_http
	bind *:80
	mode http
	acl acme path_beg /.well-known/acme-challenge/
{{range $a := .HTTPApps}}
	# HTTP app: {{$a.Application.Name}} ({{$a.Application.PublicHost}})
	acl http_app_{{$a.ACLTag}}_host hdr(host) -i {{$a.Application.PublicHost}}
{{end}}
{{- if .RedirectApps}}
	acl redir_fe_any_host hdr(host) -i {{range $i, $a := .RedirectApps}}{{if $i}} {{end}}{{$a.Application.PublicHost}}{{end}}
	http-request redirect scheme https code 301 if redir_fe_any_host !acme
{{- end}}
{{- if .HasHTTPSFrontend}}
{{- if .HTTPApps}}
	acl fe_http_keeps_plain hdr(host) -i {{range $i, $a := .HTTPApps}}{{if $i}} {{end}}{{$a.Application.PublicHost}}{{end}}
	http-request redirect scheme https code 301 if !acme !fe_http_keeps_plain
{{- else}}
	http-request redirect scheme https code 301 if !acme
{{- end}}
{{- end}}
	use_backend bk_acme if acme
{{range $a := .HTTPApps}}
	use_backend {{backendName $a.Application.PublicHost}} if http_app_{{$a.ACLTag}}_host
{{end}}
{{- if not .HasHTTPSFrontend}}
	default_backend bk_http_default
{{- end}}

# ACME challenges served by easy-wafd local listener (see scripts / docs)
backend bk_acme
	mode http
	server acme 127.0.0.1:8089 check
{{if not .HasHTTPSFrontend}}

# :80 catch-all when there is no fe_https (plain HTTP edge only)
backend bk_http_default
	mode http
	http-request deny deny_status 404
{{end}}

{{if .HasHTTPSFrontend}}
# HTTPS edge — one bind, many PEMs in crt-list → SNI picks cert; Host header routes to backends (single WAN IP).
frontend fe_https
	bind *:443 ssl crt-list {{.CRTListPath}} alpn h2,http/1.1
	mode http
	option forwardfor
	http-request set-header X-Forwarded-Proto https
	http-response set-header Strict-Transport-Security "max-age=15552000; includeSubDomains" if { ssl_fc }
{{if and $.UseCrowdSecFilter $.HasHTTPSFrontend}}
	# CrowdSec SPOE — engine id must match spoe-agent section name in {{.Settings.SPOEConfigPath}}
	filter spoe engine {{.Settings.CrowdSecEngineName}} config {{.Settings.SPOEConfigPath}}
{{end}}
	# Universal blocks (all vhosts)
	acl p_git     path_beg /.git
	acl p_env     path_beg /.env
	http-request deny deny_status 403 if p_git || p_env
	acl bad_method method TRACE CONNECT
	http-request deny deny_status 405 if bad_method
{{range $i, $a := .HTTPSApps}}
	# === Application: {{$a.Application.Name}} ({{$a.Application.PublicHost}}) ===
	acl app_{{$a.ACLTag}}_host hdr(host) -i {{$a.Application.PublicHost}}
{{- if and $.UseIPAllowlist $a.Application.Security.IPAllowlistEnabled}}
	acl app_{{$a.ACLTag}}_white src -f {{$.IPAllowlistMapPath}}
	http-request allow if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_white
{{- end}}
{{- if and $.UseIPBlacklist $a.Application.Security.IPBlacklistEnabled}}
	acl app_{{$a.ACLTag}}_black src -f {{$.IPBlacklistMapPath}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_black
{{- end}}
{{- if $a.UsePerAppGeo}}
	acl app_{{$a.ACLTag}}_geo src -f {{$a.GeoEnforceMapPath}}
{{- if eq $a.Application.Security.GeoIPPolicy "deny"}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_geo
{{- else}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host !app_{{$a.ACLTag}}_geo
{{- end}}
{{- end}}
{{- if and $.Settings.BlockEmptyUA $a.Application.Security.BotProtectionEnabled}}
	acl app_{{$a.ACLTag}}_empty_ua req.hdr(User-Agent) -m len 0
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_empty_ua
{{- end}}
{{- if and $.UseBlockedUserAgents $a.Application.Security.BotProtectionEnabled}}
	acl app_{{$a.ACLTag}}_bad_ua req.hdr(User-Agent) -m sub -i -f {{$.BlockedUserAgentsMapPath}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_bad_ua
{{- end}}
{{- if $a.Application.Security.BasicWAFEnabled}}
	acl app_{{$a.ACLTag}}_sqli query -m reg -i (union\s+select|insert\s+into|drop\s+table|delete\s+from|update[^;]*set|;.*--)
	acl app_{{$a.ACLTag}}_sqli_path path -m reg -i (union\s+select|insert\s+into|drop\s+table|\.\./\.\.)
	acl app_{{$a.ACLTag}}_xss query -m reg -i (<script|javascript:|on(error|load|click|mouse)\s*=)
	acl app_{{$a.ACLTag}}_xss_path path -m reg -i (<script|javascript:)
	acl app_{{$a.ACLTag}}_traversal path -m reg -i \.\./
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_sqli
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_sqli_path
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_xss
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_xss_path
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_traversal
{{- end}}
{{- if $a.Application.Security.MethodFilterEnabled}}
{{- range $k, $m := $a.Profile.ExtraBlockedMethods}}
	acl app_{{$a.ACLTag}}_bm_{{$k}}_{{methodSlug $m}} method {{$m}}
	http-request deny deny_status 405 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_bm_{{$k}}_{{methodSlug $m}}
{{- end}}
{{- end}}
{{- if $a.Application.Security.PathACLEnabled}}
{{- range $j, $p := $a.Profile.BlockPaths}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host { path_beg {{$p}} }
{{- end}}
{{- end}}
{{- range $ri, $rp := $a.Application.RestrictedPaths}}
{{- $rpCidr := joinCIDRs $rp.AllowedCIDRs}}
{{- if and $rp.PathPrefix $rpCidr}}
	# Per-app restricted path: {{$a.Application.Name}} {{$rp.PathPrefix}}
	acl app_{{$a.ACLTag}}_rp_{{$ri}}_path path_beg {{$rp.PathPrefix}}
	acl app_{{$a.ACLTag}}_rp_{{$ri}}_net src {{$rpCidr}}
	http-request deny deny_status 403 if app_{{$a.ACLTag}}_host app_{{$a.ACLTag}}_rp_{{$ri}}_path !app_{{$a.ACLTag}}_rp_{{$ri}}_net
{{- end}}
{{- end}}
{{- if and $.UseCrowdSecFilter $a.Application.Security.CrowdSecEnabled}}
	http-request send-spoe-group {{$.Settings.CrowdSecEngineName}} crowdsec-req if app_{{$a.ACLTag}}_host
{{- end}}
{{end}}
{{range $a := .HTTPSApps}}
	use_backend {{backendName $a.Application.PublicHost}} if app_{{$a.ACLTag}}_host
{{end}}
	default_backend bk_not_found

backend bk_not_found
	mode http
	http-request deny deny_status 404
{{end}}

{{range $i, $a := .BackendApps}}
backend {{backendName $a.Application.PublicHost}}
	mode http
	timeout connect {{haDur $a.Profile.ConnectTimeout}}
	timeout server {{haDur $a.Profile.ServerTimeout}}
	{{- if $a.Profile.HTTPKeepAlive }}
	option http-keep-alive
	{{- else }}
	option http-server-close
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
	{{- if $a.Application.WebSocket }}
	timeout tunnel 3600s
	{{- end }}
	{{- if $a.Application.HealthPath }}
	option httpchk GET {{$a.Application.HealthPath}}
	{{- end }}
	{{- if $a.Application.BackendHTTPS }}
	server s1 {{$a.Application.BackendHost}}:{{$a.Application.BackendPort}} ssl verify none check inter 3s fall 3 rise 2
	{{- else }}
	server s1 {{$a.Application.BackendHost}}:{{$a.Application.BackendPort}} check inter 3s fall 3 rise 2
	{{- end }}
{{end}}
`

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
