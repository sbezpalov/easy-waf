package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/pemutil"
	"github.com/easy-waf/easy-waf/internal/store"
)

const settingsKeyGlobal = "global_settings_json"

// Engine coordinates render + apply + revision bookkeeping.
type Engine struct {
	StateDir string
	Store    *store.Store
	Settings config.GlobalSettings
}

// LoadSettings merges stored JSON with defaults.
func (e *Engine) LoadSettings(ctx context.Context) error {
	raw, err := e.Store.GetSetting(ctx, settingsKeyGlobal)
	if err != nil || raw == "" {
		e.Settings = config.DefaultSettings(e.StateDir)
		return nil
	}
	var s config.GlobalSettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return err
	}
	def := config.DefaultSettings(e.StateDir)
	if s.HAProxyConfigPath == "" {
		s.HAProxyConfigPath = def.HAProxyConfigPath
	}
	if s.HAProxyBinary == "" {
		s.HAProxyBinary = def.HAProxyBinary
	}
	if s.SPOEConfigPath == "" {
		s.SPOEConfigPath = def.SPOEConfigPath
	}
	if s.CrowdSecEngineName == "" {
		s.CrowdSecEngineName = def.CrowdSecEngineName
	}
	if s.GeoIPCacheTTL == 0 {
		s.GeoIPCacheTTL = def.GeoIPCacheTTL
	}
	if s.ACMERenewalInterval == 0 {
		s.ACMERenewalInterval = def.ACMERenewalInterval
	}
	if s.ACMEWebrootPath == "" {
		s.ACMEWebrootPath = def.ACMEWebrootPath
	}
	if s.IPBlacklistMapPath == "" {
		s.IPBlacklistMapPath = def.IPBlacklistMapPath
	}
	if len(s.ManagementAllowedCIDRs) == 0 {
		s.ManagementAllowedCIDRs = def.ManagementAllowedCIDRs
	}
	e.Settings = s
	return nil
}

// SaveSettings persists settings JSON.
func (e *Engine) SaveSettings(ctx context.Context) error {
	b, err := json.Marshal(e.Settings)
	if err != nil {
		return err
	}
	return e.Store.SetSetting(ctx, settingsKeyGlobal, string(b))
}

// RenderFromStore builds HAProxy config from current DB state.
func (e *Engine) RenderFromStore(ctx context.Context) (haproxy.Rendered, error) {
	if _, err := ipbl.SyncAndWrite(ctx, e.Store, e.Settings, e.StateDir); err != nil {
		return haproxy.Rendered{}, err
	}
	apps, err := e.Store.ListApplications(ctx)
	if err != nil {
		return haproxy.Rendered{}, err
	}
	certs, err := e.Store.ListCertificates(ctx)
	if err != nil {
		return haproxy.Rendered{}, err
	}
	certDir := filepath.Join(e.StateDir, "certs")
	_ = os.MkdirAll(certDir, 0o750)
	cm := map[string]config.Certificate{}
	for i := range certs {
		c := certs[i]
		if c.FullchainPath != "" && c.PEMKeyPath != "" {
			if st, err := os.Stat(c.FullchainPath); err == nil && st.Size() > 0 {
				if st2, err2 := os.Stat(c.PEMKeyPath); err2 == nil && st2.Size() > 0 {
					bundle := filepath.Join(certDir, c.ID, "bundle.pem")
					_ = os.MkdirAll(filepath.Dir(bundle), 0o750)
					if err := pemutil.WriteBundle(bundle, c.FullchainPath, c.PEMKeyPath, 0o640); err == nil {
						c.BundlePath = bundle
					}
				}
			}
		} else if c.PEMCrtPath != "" {
			c.BundlePath = c.PEMCrtPath
		}
		cm[c.ID] = c
	}
	_, _, crtListPath := haproxy.Paths(e.StateDir)
	useBL := false
	if e.Settings.IPBlacklistMapPath != "" {
		if st, err := os.Stat(e.Settings.IPBlacklistMapPath); err == nil && st.Size() > 0 {
			b, err := os.ReadFile(e.Settings.IPBlacklistMapPath)
			if err == nil && ipbl.FileHasEntries(b) {
				useBL = true
			}
		}
	}
	ri := haproxy.RenderInput{
		Settings:           e.Settings,
		Applications:       apps,
		Certificates:       cm,
		CRTListPath:        crtListPath,
		IPBlacklistMapPath: e.Settings.IPBlacklistMapPath,
		UseIPBlacklist:     useBL,
	}
	return haproxy.Render(ri)
}

// Apply renders, validates with haproxy -c, writes atomically, records revision, reloads.
func (e *Engine) Apply(ctx context.Context, label string) error {
	r, err := e.RenderFromStore(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.CRTList) == "" {
		return fmt.Errorf("TLS: crt-list would be empty — add at least one certificate with fullchain/key (bundle generated on apply) or use a placeholder PEM for lab installs")
	}
	_, cfgPath, crtListPath := haproxy.Paths(e.StateDir)
	staging := cfgPath + ".staging"
	if err := apply.WriteAtomic(staging, []byte(r.HAProxyConfig), 0o640); err != nil {
		return err
	}
	if err := apply.WriteAtomic(crtListPath, []byte(r.CRTList), 0o640); err != nil {
		return err
	}
	if os.Getenv("EASY_WAF_SKIP_VALIDATE") == "" {
		if err := apply.Validate(e.Settings.HAProxyBinary, staging); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}
	revDir := filepath.Join(e.StateDir, "revisions")
	_ = os.MkdirAll(revDir, 0o750)
	snap := filepath.Join(revDir, fmt.Sprintf("haproxy-%s.cfg", r.SHA256[:12]))
	_ = os.WriteFile(snap, []byte(r.HAProxyConfig), 0o640)

	if err := apply.WriteAtomic(cfgPath, []byte(r.HAProxyConfig), 0o640); err != nil {
		return err
	}
	if os.Getenv("EASY_WAF_SKIP_RELOAD") != "" {
		if err := e.Store.AppendRevision(ctx, label, r.SHA256, cfgPath); err != nil {
			return err
		}
		return e.Store.AppendAudit(ctx, "apply", map[string]any{"sha256": r.SHA256, "skipped_reload": true})
	}
	if err := apply.ReloadHAProxy(); err != nil {
		return err
	}
	if err := e.Store.AppendRevision(ctx, label, r.SHA256, cfgPath); err != nil {
		return err
	}
	return e.Store.AppendAudit(ctx, "apply", map[string]any{"sha256": r.SHA256, "path": cfgPath})
}
