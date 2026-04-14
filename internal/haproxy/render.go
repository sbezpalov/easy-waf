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
	"github.com/easy-waf/easy-waf/internal/profiles"
)

// AppRender pairs an enabled application with its resolved profile for templating.
type AppRender struct {
	Application config.Application
	Profile     profiles.Profile
}

// RenderInput is passed to the HAProxy template.
type RenderInput struct {
	Settings           config.GlobalSettings
	Applications       []config.Application
	Apps               []AppRender `json:"-"` // filled by Render(); enabled apps + resolved profiles
	Certificates       map[string]config.Certificate // id -> cert
	CRTListPath        string                        // absolute path to generated crt-list file on disk
	IPBlacklistMapPath string
	UseIPBlacklist     bool
}

// Rendered holds outputs and checksum for apply pipeline.
type Rendered struct {
	HAProxyConfig string
	CRTList       string
	SHA256        string
}

// Render generates HAProxy configuration and crt-list body.
func Render(in RenderInput) (Rendered, error) {
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
		p, err := profiles.Resolve(app.Profile)
		if err != nil {
			return Rendered{}, err
		}
		apps = append(apps, AppRender{Application: app, Profile: p})
	}
	in.Apps = apps

	tmpl, err := template.New("haproxy").Funcs(template.FuncMap{
		"backendName": sanitizeBackendName,
		"join":        strings.Join,
		"haDur":       formatHAProxyDuration,
		"methodSlug":  methodSlug,
	}).Parse(haproxyTemplate)
	if err != nil {
		return Rendered{}, err
	}

	crtLines := buildCRTList(in)
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
	}, nil
}

func buildCRTList(in RenderInput) []string {
	var lines []string
	seen := map[string]struct{}{}
	for _, app := range in.Applications {
		if !app.Enabled || app.CertificateID == "" {
			continue
		}
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

// haproxyTemplate follows HAProxy 3.x syntax; validate with `haproxy -c`.
const haproxyTemplate = `{{/* Easy Home WAF — generated; do not edit by hand */}}
global
	log stdout format raw local0
	maxconn 50000
	stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
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

# HTTP — ACME HTTP-01 + HTTPS redirect
frontend fe_http
	bind *:80
	mode http
	acl acme path_beg /.well-known/acme-challenge/
	use_backend bk_acme if acme
	http-request redirect scheme https code 301 unless acme

# ACME challenges served by easy-wafd local listener (see scripts / docs)
backend bk_acme
	mode http
	server acme 127.0.0.1:8089 check

# HTTPS edge — one bind, many PEMs in crt-list → SNI picks cert; Host header routes to backends (single WAN IP).
frontend fe_https
	bind *:443 ssl crt-list {{.CRTListPath}} alpn h2,http/1.1
	mode http
	option forwardfor
	http-request set-header X-Forwarded-Proto https
	http-response set-header Strict-Transport-Security "max-age=15552000; includeSubDomains" if { ssl_fc }
	# CrowdSec SPOE — engine id must match spoe-agent section name in {{.Settings.SPOEConfigPath}}
	filter spoe engine {{.Settings.CrowdSecEngineName}} config {{.Settings.SPOEConfigPath}}
	# Universal blocks (all vhosts); per-app profile paths are scoped below
	acl p_git     path_beg /.git
	acl p_env     path_beg /.env
	http-request deny deny_status 403 if p_git || p_env
	acl bad_method method TRACE CONNECT
	http-request deny deny_status 405 if bad_method
{{if .UseIPBlacklist}}
	acl ipbl_black src -f {{.IPBlacklistMapPath}}
	http-request deny deny_status 403 if ipbl_black
{{end}}
{{range $i, $a := .Apps}}
	acl host_{{backendName $a.Application.PublicHost}} hdr(host) -i {{$a.Application.PublicHost}}
{{range $j, $p := $a.Profile.BlockPaths}}
	acl bp_{{$i}}_{{$j}} path_beg {{$p}}
	http-request deny deny_status 403 if host_{{backendName $a.Application.PublicHost}} bp_{{$i}}_{{$j}}
{{end}}
{{range $k, $m := $a.Profile.ExtraBlockedMethods}}
	acl bm_{{$i}}_{{$k}}_{{methodSlug $m}} method {{$m}}
	http-request deny deny_status 405 if host_{{backendName $a.Application.PublicHost}} bm_{{$i}}_{{$k}}_{{methodSlug $m}}
{{end}}
{{end}}
{{range $a := .Apps}}
	use_backend {{backendName $a.Application.PublicHost}} if host_{{backendName $a.Application.PublicHost}}
{{end}}
	default_backend bk_not_found

backend bk_not_found
	mode http
	http-request deny deny_status 404

{{range $i, $a := .Apps}}
backend {{backendName $a.Application.PublicHost}}
	mode http
	timeout connect {{haDur $a.Profile.ConnectTimeout}}
	timeout server {{haDur $a.Profile.ServerTimeout}}
	{{- if $a.Profile.HTTPKeepAlive }}
	option http-keep-alive
	{{- else }}
	option http-server-close
	{{- end }}
	stick-table type ip size 200k expire 5m store http_req_rate(10s)
	http-request track-sc0 src
	acl rl_abuse_{{$i}} sc0_http_req_rate gt {{$a.Profile.RateLimitBurst}}
	http-request deny deny_status 429 if rl_abuse_{{$i}}
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
