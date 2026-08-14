package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/easy-waf/easy-waf/internal/metrics"
	"github.com/easy-waf/easy-waf/internal/pemutil"
	"github.com/easy-waf/easy-waf/internal/store"
)

const settingsKeyGlobal = "global_settings_json"

// haproxyApplyAdvisoryLockKey serializes artifact promotion across
// easy-waf-api and easy-waf-acmed sessions.
const haproxyApplyAdvisoryLockKey int64 = 0x455741464150504c // "EWAFAPPL"

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
	if e.GeoIP == nil {
		e.GeoIP = geoip.NewRuntime(time.Duration(e.Settings.GeoIPCacheTTL))
	}
	prov, err := geoip.ProviderForRuntime(e.GeoIP, e.Settings)
	if err != nil {
		return err
	}
	return geoip.WriteEnforceMap(ctx, prov, e.GeoIP.Cache, e.Settings, e.StateDir, blacklistCIDRs)
}

// RenderFromStore builds HAProxy config from current DB state.
func (e *Engine) RenderFromStore(ctx context.Context) (haproxy.Rendered, error) {
	syncRes, err := ipbl.SyncAndWrite(ctx, e.Store, e.Settings, e.StateDir)
	if err != nil {
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
	if err := e.WriteGeoIPEnforceMap(ctx, syncRes.AllCIDRs); err != nil {
		return haproxy.Rendered{}, err
	}
	if err := e.writePerAppGeoMaps(ctx, apps, syncRes.AllCIDRs); err != nil {
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
		if err := config.ValidateResourceID("certificate", c.ID); err != nil {
			return haproxy.Rendered{}, err
		}
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
	renderSettings := e.Settings
	renderSettings.HAProxyStatsSocketPath = metrics.StatsSocketPath(e.Settings, e.StateDir)
	ri := haproxy.RenderInput{
		Settings:                 renderSettings,
		Applications:             apps,
		Certificates:             cm,
		CRTListPath:              crtListPath,
		IPBlacklistMapPath:       e.Settings.IPBlacklistMapPath,
		IPAllowlistMapPath:       wlPath,
		UseIPBlacklist:           useBL,
		UseIPAllowlist:           useWL,
		BlockedUserAgentsMapPath: uaMapPath,
		UseBlockedUserAgents:     useBadUA,
		StateDir:                 e.StateDir,
	}
	return haproxy.Render(ri)
}

func (e *Engine) writePerAppGeoMaps(ctx context.Context, apps []config.Application, blacklistCIDRs []string) error {
	for _, a := range apps {
		out := geoip.AppEnforceMapPath(e.StateDir, a.ID)
		if !a.Enabled || !a.Security.GeoIPEnabled || !geoip.HasCountryTargets(a.Security.GeoIPCountryList) {
			if err := geoip.WriteDisabledAppEnforceMap(out); err != nil {
				return err
			}
			continue
		}
		if e.GeoIP == nil {
			e.GeoIP = geoip.NewRuntime(time.Duration(e.Settings.GeoIPCacheTTL))
		}
		prov, err := geoip.ProviderForRuntime(e.GeoIP, e.Settings)
		if err != nil {
			return err
		}
		if err := geoip.WriteAppEnforceMap(ctx, prov, e.GeoIP.Cache, a.Security.GeoIPPolicy, a.Security.GeoIPCountryList, blacklistCIDRs, out); err != nil {
			return err
		}
	}
	return nil
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
	return sha256HexFile(haproxy.LiveCfgPath(e.StateDir, e.Settings.HAProxyConfigPath))
}

func appendFailure(base *error, action string, err error) {
	if err == nil {
		return
	}
	wrapped := fmt.Errorf("%s: %w", action, err)
	if *base == nil {
		*base = wrapped
		return
	}
	*base = errors.Join(*base, wrapped)
}

func (e *Engine) finishFailedArtifactTransaction(
	tx *artifactTransaction,
	cfgPath string,
	promoted bool,
	runtimeChanged bool,
	skipReload bool,
	retErr *error,
) {
	// A successful first start has no previous runtime/config to restore. Keep
	// the valid promoted set if only later bookkeeping failed.
	if runtimeChanged && !tx.snapshot.hasFile(cfgPath) {
		return
	}
	appendFailure(retErr, "restore previous HAProxy artifacts", tx.rollback())
	if promoted && !skipReload && tx.snapshot.hasFile(cfgPath) {
		appendFailure(retErr, "reload restored HAProxy configuration", apply.ReloadHAProxy())
	}
}

// Apply renders and validates one complete managed artifact set, promotes it,
// records a full revision manifest, and reloads HAProxy. Any failure restores
// the previous files; a failed post-promotion reload also reloads that restored
// configuration when one existed.
func (e *Engine) Apply(ctx context.Context, label string) (retErr error) {
	releaseLock, err := e.Store.AcquireAdvisoryLock(ctx, haproxyApplyAdvisoryLockKey)
	if err != nil {
		return fmt.Errorf("acquire HAProxy apply lock: %w", err)
	}
	defer func() {
		appendFailure(&retErr, "release HAProxy apply lock", releaseLock())
	}()

	tx, err := e.beginArtifactTransaction()
	if err != nil {
		return fmt.Errorf("snapshot current HAProxy artifacts: %w", err)
	}
	defer func() { _ = tx.remove() }()

	cfgPath := haproxy.LiveCfgPath(e.StateDir, e.Settings.HAProxyConfigPath)
	skipReload := os.Getenv("EASY_WAF_SKIP_RELOAD") != ""
	promoted := false
	runtimeChanged := false
	var revisionSnapshot *artifactSnapshot
	defer func() {
		if retErr == nil {
			return
		}
		e.finishFailedArtifactTransaction(
			tx,
			cfgPath,
			promoted,
			runtimeChanged,
			skipReload,
			&retErr,
		)
		if revisionSnapshot != nil && !(runtimeChanged && !tx.snapshot.hasFile(cfgPath)) {
			appendFailure(&retErr, "remove failed revision snapshot", revisionSnapshot.remove())
		}
	}()

	r, err := e.RenderFromStore(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.CRTList) == "" && r.RequiresTLS {
		return fmt.Errorf("TLS: crt-list would be empty — add at least one certificate with fullchain/key (bundle generated on apply) or use a placeholder PEM for lab installs")
	}
	_, _, crtListPath := haproxy.Paths(e.StateDir)
	staging := cfgPath + ".staging"
	defer func() { _ = os.Remove(staging) }()
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
	if err := apply.WriteAtomic(cfgPath, []byte(r.HAProxyConfig), 0o640); err != nil {
		return err
	}
	promoted = true

	revisionSnapshot, err = e.createRevisionSnapshot(r.SHA256, nil)
	if err != nil {
		return fmt.Errorf("snapshot new HAProxy revision: %w", err)
	}
	if !skipReload {
		if err := apply.ReloadHAProxy(); err != nil {
			return err
		}
		runtimeChanged = true
	}
	detail := map[string]any{
		"sha256":            r.SHA256,
		"path":              cfgPath,
		"artifact_manifest": revisionSnapshot.ManifestPath,
	}
	if skipReload {
		detail["skipped_reload"] = true
	}
	if err := e.Store.AppendRevisionAndAudit(
		ctx,
		label,
		r.SHA256,
		revisionSnapshot.ManifestPath,
		"apply",
		detail,
	); err != nil {
		return err
	}
	return nil
}

// Rollback restores a full managed artifact set for new revisions. Legacy rows
// without a manifest retain cfg-only fallback behavior.
func (e *Engine) Rollback(ctx context.Context, revisionID int64) (retErr error) {
	releaseLock, err := e.Store.AcquireAdvisoryLock(ctx, haproxyApplyAdvisoryLockKey)
	if err != nil {
		return fmt.Errorf("acquire HAProxy apply lock: %w", err)
	}
	defer func() {
		appendFailure(&retErr, "release HAProxy apply lock", releaseLock())
	}()

	rev, err := e.Store.GetConfigRevision(ctx, revisionID)
	if err != nil {
		return err
	}
	if len(rev.HAProxySHA256) < 12 {
		return fmt.Errorf("invalid stored revision hash")
	}

	cfgPath := haproxy.LiveCfgPath(e.StateDir, e.Settings.HAProxyConfigPath)
	tx, err := e.beginArtifactTransaction()
	if err != nil {
		return fmt.Errorf("snapshot current HAProxy artifacts: %w", err)
	}
	defer func() { _ = tx.remove() }()

	skipReload := os.Getenv("EASY_WAF_SKIP_RELOAD") != ""
	promoted := false
	runtimeChanged := false
	var revisionSnapshot *artifactSnapshot
	defer func() {
		if retErr == nil {
			return
		}
		e.finishFailedArtifactTransaction(
			tx,
			cfgPath,
			promoted,
			runtimeChanged,
			skipReload,
			&retErr,
		)
		if revisionSnapshot != nil && !(runtimeChanged && !tx.snapshot.hasFile(cfgPath)) {
			appendFailure(&retErr, "remove failed revision snapshot", revisionSnapshot.remove())
		}
	}()

	var targetExtra []string
	if filepath.Base(filepath.Clean(rev.ContentPath)) == "manifest.json" {
		targetManifest, err := readAndVerifyArtifactManifest(rev.ContentPath)
		if err != nil {
			return fmt.Errorf("revision artifact manifest invalid: %w", err)
		}
		if !strings.EqualFold(targetManifest.ConfigSHA256, rev.HAProxySHA256) {
			return fmt.Errorf("revision artifact manifest config checksum mismatch")
		}
		targetExtra = artifactManifestPaths(targetManifest)
		currentManaged, err := e.managedArtifactPaths(targetExtra)
		if err != nil {
			return err
		}
		if _, err := restoreArtifactManifest(rev.ContentPath, currentManaged, cfgPath); err != nil {
			return fmt.Errorf("restore revision artifacts: %w", err)
		}
		promoted = true
	} else {
		snapPath := filepath.Join(e.StateDir, "revisions", fmt.Sprintf("haproxy-%s.cfg", rev.HAProxySHA256[:12]))
		b, err := os.ReadFile(snapPath)
		if err != nil {
			return fmt.Errorf("revision snapshot not found: %w", err)
		}
		got := sha256HexBytes(b)
		if got != rev.HAProxySHA256 {
			return fmt.Errorf("revision snapshot corrupt: sha256 mismatch")
		}
		if curSHA, err := sha256HexFile(cfgPath); err == nil && curSHA == got {
			return fmt.Errorf("already using this configuration")
		}
		staging := cfgPath + ".staging"
		defer func() { _ = os.Remove(staging) }()
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
		promoted = true
	}

	got, err := sha256HexFile(cfgPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, rev.HAProxySHA256) {
		return fmt.Errorf("restored revision config checksum mismatch")
	}
	if os.Getenv("EASY_WAF_SKIP_VALIDATE") == "" {
		if err := apply.Validate(e.Settings.HAProxyBinary, cfgPath); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	revisionSnapshot, err = e.createRevisionSnapshot(got, targetExtra)
	if err != nil {
		return fmt.Errorf("snapshot rollback revision: %w", err)
	}
	if !skipReload {
		if err := apply.ReloadHAProxy(); err != nil {
			return err
		}
		runtimeChanged = true
	}
	label := fmt.Sprintf("rollback from %s", rev.HAProxySHA256[:12])
	detail := map[string]any{
		"sha256":            got,
		"path":              cfgPath,
		"from_revision_id":  revisionID,
		"from_label":        rev.Label,
		"artifact_manifest": revisionSnapshot.ManifestPath,
	}
	if skipReload {
		detail["skipped_reload"] = true
	}
	if err := e.Store.AppendRevisionAndAudit(
		ctx,
		label,
		got,
		revisionSnapshot.ManifestPath,
		"rollback",
		detail,
	); err != nil {
		return err
	}
	return nil
}
