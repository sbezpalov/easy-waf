package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/blockedua"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/ipwl"
	"github.com/easy-waf/easy-waf/internal/pemutil"
	"github.com/easy-waf/easy-waf/internal/store"
)

const settingsKeyGlobal = "global_settings_json"

// Engine coordinates render + apply + revision bookkeeping.
type Engine struct {
	StateDir string
	Store    *store.Store
	Settings config.GlobalSettings
	// GeoIP is optional in-memory cache + API lookups (initialized lazily).
	GeoIP *geoip.Runtime
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
	var settingsKeyProbe struct {
		WAFBasic   *bool `json:"waf_basic_rules_enabled"`
		BlockEmpty *bool `json:"block_empty_ua"`
	}
	_ = json.Unmarshal([]byte(raw), &settingsKeyProbe)
	if settingsKeyProbe.WAFBasic == nil {
		s.WAFBasicRulesEnabled = def.WAFBasicRulesEnabled
	}
	if settingsKeyProbe.BlockEmpty == nil {
		s.BlockEmptyUA = def.BlockEmptyUA
	}
	if s.HAProxyConfigPath == "" {
		s.HAProxyConfigPath = def.HAProxyConfigPath
	}
	if s.HAProxyStatsSocketPath == "" {
		s.HAProxyStatsSocketPath = def.HAProxyStatsSocketPath
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
	if s.IPAllowlistMapPath == "" {
		s.IPAllowlistMapPath = def.IPAllowlistMapPath
	}
	if s.BlockedUserAgentsMapPath == "" {
		s.BlockedUserAgentsMapPath = def.BlockedUserAgentsMapPath
	}
	if s.GeoIPEnforceMapPath == "" {
		s.GeoIPEnforceMapPath = def.GeoIPEnforceMapPath
	}
	if strings.TrimSpace(s.GeoIPProvider) == "" {
		s.GeoIPProvider = def.GeoIPProvider
	}
	if strings.TrimSpace(s.GeoIPDefaultPolicy) == "" {
		s.GeoIPDefaultPolicy = def.GeoIPDefaultPolicy
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

// WriteGeoIPEnforceMap refreshes the HAProxy GeoIP batch map from merged blacklist CIDRs.
func (e *Engine) WriteGeoIPEnforceMap(ctx context.Context, blacklistCIDRs []string) error {
	if !e.Settings.GeoIPEnabled {
		return geoip.WriteDisabledEnforceMap(e.Settings, e.StateDir)
	}
	prov, err := geoip.NewProviderForSettings(e.Settings)
	if err != nil {
		return err
	}
	if e.GeoIP == nil {
		e.GeoIP = geoip.NewRuntime(time.Duration(e.Settings.GeoIPCacheTTL))
	}
	return geoip.WriteEnforceMap(ctx, prov, e.GeoIP.Cache, e.Settings, e.StateDir, blacklistCIDRs)
}

// RenderFromStore builds HAProxy config from current DB state.
func (e *Engine) RenderFromStore(ctx context.Context) (haproxy.Rendered, error) {
	syncRes, err := ipbl.SyncAndWrite(ctx, e.Store, e.Settings, e.StateDir)
	if err != nil {
		return haproxy.Rendered{}, err
	}
	if err := e.WriteGeoIPEnforceMap(ctx, syncRes.AllCIDRs); err != nil {
		return haproxy.Rendered{}, err
	}
	wlPath := ipwl.MapPath(e.Settings, e.StateDir)
	if err := ipwl.WriteLocalMap(ctx, e.Store, wlPath); err != nil {
		return haproxy.Rendered{}, err
	}
	uaMapPath := blockedua.MapPath(e.Settings, e.StateDir)
	if err := blockedua.WriteMap(ctx, e.Store, uaMapPath); err != nil {
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
	useWL := ipwl.UseInRender(e.Settings.IPWLEnabled, wlPath)
	useBadUA := blockedua.UseInRender(e.Settings.BlockedUserAgentsEnabled, uaMapPath)
	geoPath := geoip.EnforceMapPath(e.Settings, e.StateDir)
	useGeo := geoip.UseEnforceMapInRender(e.Settings.GeoIPEnabled, geoPath)
	ri := haproxy.RenderInput{
		Settings:                 e.Settings,
		Applications:             apps,
		Certificates:             cm,
		CRTListPath:              crtListPath,
		IPBlacklistMapPath:       e.Settings.IPBlacklistMapPath,
		IPAllowlistMapPath:       wlPath,
		UseIPBlacklist:           useBL,
		UseIPAllowlist:           useWL,
		BlockedUserAgentsMapPath: uaMapPath,
		UseBlockedUserAgents:     useBadUA,
		GeoIPEnforceMapPath:      geoPath,
		UseGeoIPEnforce:          useGeo,
	}
	return haproxy.Render(ri)
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256HexFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256HexBytes(b), nil
}

// LiveHAProxySHA256 returns the sha256 hex digest of the current live haproxy.cfg.
func (e *Engine) LiveHAProxySHA256() (string, error) {
	_, cfgPath, _ := haproxy.Paths(e.StateDir)
	return sha256HexFile(cfgPath)
}

func (e *Engine) reloadAppendRevisionAndAudit(ctx context.Context, label, sha256Hex, cfgPath, auditAction string, auditDetail map[string]any) error {
	if os.Getenv("EASY_WAF_SKIP_RELOAD") != "" {
		if err := e.Store.AppendRevision(ctx, label, sha256Hex, cfgPath); err != nil {
			return err
		}
		auditDetail["skipped_reload"] = true
		return e.Store.AppendAudit(ctx, auditAction, auditDetail)
	}
	if err := apply.ReloadHAProxy(); err != nil {
		return err
	}
	if err := e.Store.AppendRevision(ctx, label, sha256Hex, cfgPath); err != nil {
		return err
	}
	return e.Store.AppendAudit(ctx, auditAction, auditDetail)
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
	return e.reloadAppendRevisionAndAudit(ctx, label, r.SHA256, cfgPath, "apply", map[string]any{"sha256": r.SHA256, "path": cfgPath})
}

// Rollback restores live haproxy.cfg from the on-disk snapshot for a stored revision,
// runs haproxy -c, reloads, and appends a new revision row labeled rollback from <short sha>.
func (e *Engine) Rollback(ctx context.Context, revisionID int64) error {
	rev, err := e.Store.GetConfigRevision(ctx, revisionID)
	if err != nil {
		return err
	}
	if len(rev.HAProxySHA256) < 12 {
		return fmt.Errorf("invalid stored revision hash")
	}
	snapPath := filepath.Join(e.StateDir, "revisions", fmt.Sprintf("haproxy-%s.cfg", rev.HAProxySHA256[:12]))
	b, err := os.ReadFile(snapPath)
	if err != nil {
		return fmt.Errorf("revision snapshot not found: %w", err)
	}
	got := sha256HexBytes(b)
	if got != rev.HAProxySHA256 {
		return fmt.Errorf("revision snapshot corrupt: sha256 mismatch")
	}
	_, cfgPath, _ := haproxy.Paths(e.StateDir)
	if curSHA, err := sha256HexFile(cfgPath); err == nil && curSHA == got {
		return fmt.Errorf("already using this configuration")
	}
	staging := cfgPath + ".staging"
	if err := apply.WriteAtomic(staging, b, 0o640); err != nil {
		return err
	}
	if os.Getenv("EASY_WAF_SKIP_VALIDATE") == "" {
		if err := apply.Validate(e.Settings.HAProxyBinary, staging); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}
	if err := apply.WriteAtomic(cfgPath, b, 0o640); err != nil {
		return err
	}
	label := fmt.Sprintf("rollback from %s", rev.HAProxySHA256[:12])
	detail := map[string]any{
		"sha256":           got,
		"path":             cfgPath,
		"from_revision_id": revisionID,
		"from_label":       rev.Label,
	}
	return e.reloadAppendRevisionAndAudit(ctx, label, got, cfgPath, "rollback", detail)
}
