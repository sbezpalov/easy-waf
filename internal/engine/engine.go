// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

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
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/blockedua"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/envflag"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/ipwl"
	"github.com/easy-waf/easy-waf/internal/metrics"
	"github.com/easy-waf/easy-waf/internal/pemutil"
	"github.com/easy-waf/easy-waf/internal/store"
)

const settingsKeyGlobal = "global_settings_json"

// Recovery must remain possible after the caller's apply deadline expires.
const recoveryReloadTimeout = 30 * time.Second

// haproxyApplyAdvisoryLockKey serializes artifact promotion across
// easy-waf-api and easy-waf-acmed sessions.
const haproxyApplyAdvisoryLockKey int64 = 0x455741464150504c // "EWAFAPPL"

// settingsAdvisoryLockKey serializes global settings RMW across processes
// (api vs admin CLI), complementing the in-process settingsMu.
const settingsAdvisoryLockKey int64 = 0x4557414653455453 // "EWAFSETS"

// ApplyOrUndoAdvisoryLockKey serializes application mutations and edge operations
// so a render cannot observe an application change before its apply or undo ends.
const ApplyOrUndoAdvisoryLockKey int64 = 0x45574146414F5501 // "EWAFAO1"

// Engine coordinates render + apply + revision bookkeeping. It is shared by
// every API request goroutine, so its settings and GeoIP runtime sit behind a
// mutex: read them with Settings / GeoIP, change them with SetSettings or
// UpdateSettings, never by reaching into the struct.
type Engine struct {
	StateDir string
	Store    *store.Store

	mu       sync.RWMutex
	settings config.GlobalSettings
	geo      *geoip.Runtime
	// geoCfgMu orders GeoIP runtime reconfiguration, so concurrent
	// SetSettings calls cannot leave the runtime bound to an older value.
	geoCfgMu sync.Mutex

	// applySem serializes Apply, Rollback and WithApplyLock inside one
	// process; the PostgreSQL advisory lock does the same across processes.
	// It is a one-slot channel rather than a sync.Mutex so that waiting for
	// it honors the caller's context while waiting for another apply.
	applySem     chan struct{}
	applySemOnce sync.Once
	// settingsMu serializes read-modify-write of the stored settings.
	settingsMu sync.Mutex
}

// New returns an engine with the given initial settings.
func New(stateDir string, st *store.Store, settings config.GlobalSettings) *Engine {
	return &Engine{StateDir: stateDir, Store: st, settings: settings}
}

// Settings returns a copy of the current settings. Slices inside are shared
// and must be treated as read-only.
func (e *Engine) Settings() config.GlobalSettings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

// SetSettings replaces the in-memory settings (it does not persist them) and
// rebinds the GeoIP runtime to them: a provider or database change retires the
// cached reader and the cached countries, a TTL change applies at once.
func (e *Engine) SetSettings(s config.GlobalSettings) {
	e.mu.Lock()
	e.settings = s
	geo := e.geo
	e.mu.Unlock()
	if geo != nil {
		// Configure with whatever is current once we hold geoCfgMu: if
		// another SetSettings ran meanwhile, its value wins, as it does for
		// e.settings.
		e.geoCfgMu.Lock()
		geo.Configure(e.Settings())
		e.geoCfgMu.Unlock()
	}
}

// GeoIP returns the in-memory GeoIP cache and provider runtime, creating it on
// first use.
func (e *Engine) GeoIP() *geoip.Runtime {
	e.mu.RLock()
	g := e.geo
	e.mu.RUnlock()
	if g != nil {
		return g
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.geo == nil {
		e.geo = geoip.NewRuntime(time.Duration(e.settings.GeoIPCacheTTL))
		e.geo.Configure(e.settings)
	}
	return e.geo
}

// UpdateSettings re-reads the stored settings, applies fn to them, persists
// the result and makes it current. Starting from the database rather than the
// in-memory copy means a change made meanwhile by another process (the admin
// CLI, say) is kept instead of being overwritten.
func (e *Engine) UpdateSettings(ctx context.Context, fn func(config.GlobalSettings) (config.GlobalSettings, error)) (config.GlobalSettings, error) {
	release, err := e.Store.AcquireAdvisoryLock(ctx, settingsAdvisoryLockKey)
	if err != nil {
		return config.GlobalSettings{}, err
	}
	defer func() { _ = release() }()
	e.settingsMu.Lock()
	defer e.settingsMu.Unlock()
	cur, err := e.readSettings(ctx)
	if err != nil {
		return config.GlobalSettings{}, err
	}
	next, err := fn(cur)
	if err != nil {
		return config.GlobalSettings{}, err
	}
	if err := e.saveSettings(ctx, next); err != nil {
		return config.GlobalSettings{}, err
	}
	e.SetSettings(next)
	return next, nil
}

// LoadSettings replaces the in-memory settings with the stored ones merged
// over defaults. A database error is returned, never papered over with
// defaults: rendering the edge from defaults would silently drop the
// operator's protections.
func (e *Engine) LoadSettings(ctx context.Context) error {
	_, err := e.reloadSettings(ctx)
	return err
}

// reloadSettings reads the stored settings and makes them current. It holds
// settingsMu like UpdateSettings, so a concurrent update cannot be followed
// by this older read overwriting it in memory.
func (e *Engine) reloadSettings(ctx context.Context) (config.GlobalSettings, error) {
	e.settingsMu.Lock()
	defer e.settingsMu.Unlock()
	s, err := e.readSettings(ctx)
	if err != nil {
		return config.GlobalSettings{}, err
	}
	e.SetSettings(s)
	return s, nil
}

func (e *Engine) readSettings(ctx context.Context) (config.GlobalSettings, error) {
	raw, err := e.Store.GetSetting(ctx, settingsKeyGlobal)
	if err != nil {
		return config.GlobalSettings{}, fmt.Errorf("load settings: %w", err)
	}
	if raw == "" {
		return config.DefaultSettings(e.StateDir), nil
	}
	var s config.GlobalSettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return config.GlobalSettings{}, fmt.Errorf("decode settings: %w", err)
	}
	def := config.DefaultSettings(e.StateDir)
	var settingsKeyProbe struct {
		WAFBasic   *bool `json:"waf_basic_rules_enabled"`
		BlockEmpty *bool `json:"block_empty_ua"`
		SecHeaders *bool `json:"security_headers_enabled"`
	}
	_ = json.Unmarshal([]byte(raw), &settingsKeyProbe)
	if settingsKeyProbe.WAFBasic == nil {
		s.WAFBasicRulesEnabled = def.WAFBasicRulesEnabled
	}
	if settingsKeyProbe.BlockEmpty == nil {
		s.BlockEmptyUA = def.BlockEmptyUA
	}
	if settingsKeyProbe.SecHeaders == nil {
		s.SecurityHeadersEnabled = def.SecurityHeadersEnabled
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
	return s, nil
}

// SaveSettings persists the current in-memory settings.
func (e *Engine) SaveSettings(ctx context.Context) error {
	e.settingsMu.Lock()
	defer e.settingsMu.Unlock()
	return e.saveSettings(ctx, e.Settings())
}

func (e *Engine) saveSettings(ctx context.Context, s config.GlobalSettings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return e.Store.SetSetting(ctx, settingsKeyGlobal, string(b))
}

// SyncIPBL refreshes the IP blacklist, allowlist and GeoIP enforce maps
// outside a full apply. Network feed downloads run outside the apply lock;
// the lock covers only merge + atomic map promote (and allowlist/GeoIP maps).
func (e *Engine) SyncIPBL(ctx context.Context) (res ipbl.SyncResult, err error) {
	cfg, err := e.reloadSettings(ctx)
	if err != nil {
		return res, err
	}
	if err := ipbl.PrefetchFeeds(ctx, e.Store, cfg, e.StateDir); err != nil {
		return res, err
	}
	err = e.WithApplyLock(ctx, func() error {
		// What is stored now, not this process's copy: feeds switched off
		// from the admin CLI or another instance must be honored here too.
		cfg, err := e.refreshForApply(ctx)
		if err != nil {
			return err
		}
		r, err := ipbl.SyncAndWriteOpts(ctx, e.Store, cfg, e.StateDir, ipbl.SyncOptions{SkipFetch: true})
		if err != nil {
			return err
		}
		if err := ipwl.WriteLocalMap(ctx, e.Store, ipwl.MapPath(cfg, e.StateDir)); err != nil {
			return err
		}
		res = r
		return e.writeGeoIPEnforceMap(ctx, cfg, r.AllCIDRs, nil)
	})
	return res, err
}

// writeGeoIPEnforceMap refreshes the HAProxy GeoIP batch map from merged
// blacklist CIDRs. geo memoizes lookups across the maps of one render; nil
// means a fresh one.
func (e *Engine) writeGeoIPEnforceMap(ctx context.Context, cfg config.GlobalSettings, blacklistCIDRs []string, geo *renderGeo) error {
	if !cfg.GeoIPEnabled {
		return geoip.WriteDisabledEnforceMap(cfg, e.StateDir)
	}
	if geo == nil {
		geo = e.newRenderGeo(cfg)
		defer geo.close()
	}
	prov, err := geo.provider()
	if err != nil {
		return err
	}
	return geoip.WriteEnforceMap(ctx, prov, nil, cfg, e.StateDir, blacklistCIDRs)
}

// renderGeo resolves countries for one render: every address is looked up at
// most once however many maps (global and per application) need it.
type renderGeo struct {
	rt      *geoip.Runtime
	cfg     config.GlobalSettings
	memo    *geoip.MemoProvider
	release func()
}

func (e *Engine) newRenderGeo(cfg config.GlobalSettings) *renderGeo {
	return &renderGeo{rt: e.GeoIP(), cfg: cfg}
}

func (g *renderGeo) provider() (geoip.GeoProvider, error) {
	if g.memo != nil {
		return g.memo, nil
	}
	res, release, err := g.rt.Resolver(g.cfg)
	if err != nil {
		return nil, err
	}
	g.memo, g.release = geoip.NewMemoProvider(res), release
	return g.memo, nil
}

// close releases what the render's resolver opened.
func (g *renderGeo) close() {
	if g.release != nil {
		g.release()
		g.release = nil
	}
}

// RenderFromStore builds HAProxy config and generated maps under the same
// locks as apply, so it cannot overwrite artifacts during another transaction.
func (e *Engine) RenderFromStore(ctx context.Context) (rendered haproxy.Rendered, retErr error) {
	cfg := e.Settings()
	_ = ipbl.PrefetchFeeds(ctx, e.Store, cfg, e.StateDir)
	retErr = e.WithApplyLock(ctx, func() error {
		cfg, err := e.refreshForApply(ctx)
		if err != nil {
			return err
		}
		rendered, err = e.renderFromStore(ctx, cfg)
		return err
	})
	return rendered, retErr
}

func (e *Engine) reloadPendingPath() string {
	return filepath.Join(e.StateDir, "haproxy", ".reload-pending")
}

func (e *Engine) markReloadPending() error {
	path := e.reloadPendingPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func (e *Engine) clearReloadPending() {
	_ = os.Remove(e.reloadPendingPath())
}

func (e *Engine) hasReloadPending() bool {
	_, err := os.Stat(e.reloadPendingPath())
	return err == nil
}

// renderFromStore renders with one settings snapshot, so a concurrent settings
// change cannot mix two configurations into one artifact set.
// Callers that hold the apply lock must PrefetchFeeds first so this only
// merges cached feeds (SkipFetch).
func (e *Engine) renderFromStore(ctx context.Context, cfg config.GlobalSettings) (haproxy.Rendered, error) {
	syncRes, err := ipbl.SyncAndWriteOpts(ctx, e.Store, cfg, e.StateDir, ipbl.SyncOptions{SkipFetch: true})
	if err != nil {
		return haproxy.Rendered{}, err
	}
	wlPath := ipwl.MapPath(cfg, e.StateDir)
	if err := ipwl.WriteLocalMap(ctx, e.Store, wlPath); err != nil {
		return haproxy.Rendered{}, err
	}
	uaMapPath := blockedua.MapPath(cfg, e.StateDir)
	if err := blockedua.WriteMap(ctx, e.Store, uaMapPath); err != nil {
		return haproxy.Rendered{}, err
	}
	apps, err := e.Store.ListApplications(ctx)
	if err != nil {
		return haproxy.Rendered{}, err
	}
	geo := e.newRenderGeo(cfg)
	defer geo.close()
	if err := e.writeGeoIPEnforceMap(ctx, cfg, syncRes.AllCIDRs, geo); err != nil {
		return haproxy.Rendered{}, err
	}
	if err := e.writePerAppGeoMaps(ctx, apps, syncRes.AllCIDRs, geo); err != nil {
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
						c.BundlePath = filepath.ToSlash(bundle)
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
	if cfg.IPBlacklistMapPath != "" {
		if st, err := os.Stat(cfg.IPBlacklistMapPath); err == nil && st.Size() > 0 {
			b, err := os.ReadFile(cfg.IPBlacklistMapPath)
			if err == nil && ipbl.FileHasEntries(b) {
				useBL = true
			}
		}
	}
	useWL := ipwl.UseInRender(cfg.IPWLEnabled, wlPath)
	useBadUA := blockedua.UseInRender(cfg.BlockedUserAgentsEnabled, uaMapPath)
	renderSettings := cfg
	renderSettings.HAProxyStatsSocketPath = metrics.StatsSocketPath(cfg, e.StateDir)
	ri := haproxy.RenderInput{
		Settings:                 renderSettings,
		Applications:             apps,
		Certificates:             cm,
		CRTListPath:              filepath.ToSlash(crtListPath),
		IPBlacklistMapPath:       cfg.IPBlacklistMapPath,
		IPAllowlistMapPath:       wlPath,
		UseIPBlacklist:           useBL,
		UseIPAllowlist:           useWL,
		BlockedUserAgentsMapPath: uaMapPath,
		UseBlockedUserAgents:     useBadUA,
		StateDir:                 e.StateDir,
	}
	return haproxy.Render(ri)
}

func (e *Engine) writePerAppGeoMaps(ctx context.Context, apps []config.Application, blacklistCIDRs []string, geo *renderGeo) error {
	for _, a := range apps {
		out := geoip.AppEnforceMapPath(e.StateDir, a.ID)
		if !a.Enabled || !a.Security.GeoIPEnabled || !geoip.HasCountryTargets(a.Security.GeoIPCountryList) {
			if err := geoip.WriteDisabledAppEnforceMap(out); err != nil {
				return err
			}
			continue
		}
		prov, err := geo.provider()
		if err != nil {
			return err
		}
		if err := geoip.WriteAppEnforceMap(ctx, prov, nil, a.Security.GeoIPPolicy, a.Security.GeoIPCountryList, blacklistCIDRs, out); err != nil {
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
	return sha256HexFile(haproxy.LiveCfgPath(e.StateDir, e.Settings().HAProxyConfigPath))
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
	restoreErr := tx.rollback()
	if restoreErr != nil {
		appendFailure(retErr, fmt.Sprintf("restore previous HAProxy artifacts (recovery manifest retained at %s)", tx.snapshot.ManifestPath), restoreErr)
		// Reload only a completely restored set. Loading a partial recovery
		// could replace a still-running edge with mixed configuration and maps.
		return
	}
	if promoted && tx.snapshot.hasFile(cfgPath) {
		// The reload loads whatever certificate files are on disk now,
		// renewed ones included (a rollback does not restore PEMs).
		certs := e.certsBeforeLoad()
		if skipReload {
			e.saveLoadedCerts(certs)
			return
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), recoveryReloadTimeout)
		defer cancel()
		reloadErr := apply.ReloadHAProxy(recoveryCtx)
		if reloadErr != nil {
			tx.retainRecovery = true
			appendFailure(retErr, fmt.Sprintf("reload restored HAProxy configuration (recovery manifest retained at %s)", tx.snapshot.ManifestPath), reloadErr)
			return
		}
		e.saveLoadedCerts(certs)
	}
}

// WithApplyLock runs fn while holding the HAProxy apply lock, so files fn
// writes (for example renewed PEMs that a render reads) never change in the
// middle of another process's Apply or Rollback. fn must not call another
// operation that acquires the apply lock.
func (e *Engine) WithApplyLock(ctx context.Context, fn func() error) (retErr error) {
	release, err := e.lockApply(ctx)
	if err != nil {
		return err
	}
	defer func() {
		appendFailure(&retErr, "release apply locks", release())
	}()
	return fn()
}

// lockApply takes the mutation gate before the local and cross-process apply
// locks. A handler holding a mutation lease may apply without reacquiring it.
func (e *Engine) lockApply(ctx context.Context) (func() error, error) {
	return e.lockApplyWith(ctx, e.Store.AcquireAdvisoryLock)
}

func (e *Engine) lockApplyWith(ctx context.Context, acquire advisoryLockAcquire) (release func() error, retErr error) {
	_, releaseMutation, err := e.lockApplicationMutation(ctx, acquire)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			appendFailure(&retErr, "release application mutation lock", releaseMutation())
		}
	}()
	e.applySemOnce.Do(func() { e.applySem = make(chan struct{}, 1) })
	select {
	case e.applySem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("acquire HAProxy apply lock: %w", ctx.Err())
	}
	unlock := func() { <-e.applySem }
	releaseEdge, err := acquire(ctx, haproxyApplyAdvisoryLockKey)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("acquire HAProxy apply lock: %w", err)
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			defer unlock()
			appendFailure(&releaseErr, "release HAProxy apply lock", releaseEdge())
			appendFailure(&releaseErr, "release application mutation lock", releaseMutation())
		})
		return releaseErr
	}, nil
}

// refreshForApply re-reads settings under the apply lock so the render uses
// what is stored now, not a copy this process loaded earlier (the admin CLI
// or another API instance may have changed it).
func (e *Engine) refreshForApply(ctx context.Context) (config.GlobalSettings, error) {
	return e.reloadSettings(ctx)
}

// Apply renders and validates one complete managed artifact set, promotes it,
// records a full revision manifest, and reloads HAProxy. Failure before a
// successful reload restores the previous files. Later failures return an
// AppliedError and keep the applied configuration in place.
func (e *Engine) Apply(ctx context.Context, label string) error {
	applied, err := e.apply(ctx, label, false)
	err = appliedOperationError(applied, err)
	e.notifyApplyFailure(label, err)
	return err
}

// ApplyIfChanged renders the artifact set and applies it only when it differs
// from what is on disk, reporting whether it did. It is the reconcile run when
// the API starts: after an upgrade that changes the template, or a database
// restored behind the edge's back, the edge is brought in line without a
// reload (or an empty revision) on every ordinary restart.
func (e *Engine) ApplyIfChanged(ctx context.Context, label string) (bool, error) {
	applied, err := e.apply(ctx, label, true)
	err = appliedOperationError(applied, err)
	e.notifyApplyFailure(label, err)
	return applied, err
}

func (e *Engine) apply(ctx context.Context, label string, onlyIfChanged bool) (applied bool, retErr error) {
	if err := config.ValidateRevisionLabel(label); err != nil {
		return false, err
	}
	// Prefetch IPBL feeds before the apply lock so HTTP downloads do not
	// serialize every Apply behind network RTT.
	if peek, err := e.reloadSettings(ctx); err == nil {
		_ = ipbl.PrefetchFeeds(ctx, e.Store, peek, e.StateDir)
	}

	releaseLock, err := e.lockApply(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		appendFailure(&retErr, "release apply locks", releaseLock())
	}()
	cfg, err := e.refreshForApply(ctx)
	if err != nil {
		return false, err
	}

	tx, err := e.beginArtifactTransaction(cfg)
	if err != nil {
		return false, fmt.Errorf("snapshot current HAProxy artifacts: %w", err)
	}
	defer func() { _ = tx.remove() }()

	cfgPath := haproxy.LiveCfgPath(e.StateDir, cfg.HAProxyConfigPath)
	skipReload := envflag.Enabled("EASY_WAF_SKIP_RELOAD")
	promoted := false
	runtimeChanged := false
	var revisionSnapshot *artifactSnapshot
	defer func() {
		if retErr == nil {
			return
		}
		// After a successful reload the live edge is the new config. Rolling
		// it back because revision/audit bookkeeping failed flaps traffic for
		// a durable bookkeeping problem — leave the runtime as-is.
		if runtimeChanged {
			return
		}
		// In skip-reload mode a failed bookkeeping step still restores the
		// artifacts; report that outcome instead of claiming they were kept.
		applied = false
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

	r, err := e.renderFromStore(ctx, cfg)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(r.CRTList) == "" && r.RequiresTLS {
		return false, fmt.Errorf("TLS: crt-list would be empty — add at least one certificate with fullchain/key (bundle generated on apply) or use a placeholder PEM for lab installs")
	}
	_, _, crtListPath := haproxy.Paths(e.StateDir)
	staging := cfgPath + ".staging"
	defer func() { _ = os.Remove(staging) }()
	if err := apply.WriteAtomic(staging, []byte(r.HAProxyConfig), 0o640); err != nil {
		return false, err
	}
	if err := apply.WriteAtomic(crtListPath, []byte(r.CRTList), 0o640); err != nil {
		return false, err
	}
	forceReload := e.hasReloadPending()
	if onlyIfChanged && !forceReload {
		same, err := e.artifactsUnchanged(cfg, tx.snapshot, cfgPath, []byte(r.HAProxyConfig))
		if err != nil {
			return false, err
		}
		if same {
			// Config and maps match; a certificate renewed in place shows up
			// only in the PEM files the crt-list names.
			changed, err := e.certsChangedSinceLoad()
			if err != nil {
				return false, err
			}
			if !changed {
				return false, nil
			}
		}
	}
	if !envflag.Enabled("EASY_WAF_SKIP_VALIDATE") {
		if err := apply.Validate(ctx, cfg.HAProxyBinary, staging); err != nil {
			return false, fmt.Errorf("validation failed: %w", err)
		}
	}
	// Durable "reload required" before promote: a crash after writing live
	// artifacts must not let ApplyIfChanged skip reload on the next start.
	if err := e.markReloadPending(); err != nil {
		return false, fmt.Errorf("mark reload pending: %w", err)
	}
	if err := apply.WriteAtomic(cfgPath, []byte(r.HAProxyConfig), 0o640); err != nil {
		return false, err
	}
	promoted = true

	revisionSnapshot, err = e.createRevisionSnapshot(cfg, r.SHA256, nil)
	if err != nil {
		return false, fmt.Errorf("snapshot new HAProxy revision: %w", err)
	}
	certs := e.certsBeforeLoad()
	if !skipReload {
		if err := apply.ReloadHAProxy(ctx); err != nil {
			return false, err
		}
		runtimeChanged = true
	}
	e.saveLoadedCerts(certs)
	e.clearReloadPending()
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
		return true, fmt.Errorf("record HAProxy revision and audit: %w", err)
	}
	return true, nil
}

// Rollback restores a full managed artifact set for new revisions. Legacy rows
// without a manifest retain cfg-only fallback behavior.
func (e *Engine) Rollback(ctx context.Context, revisionID int64) (retErr error) {
	runtimeChanged := false
	defer func() { retErr = appliedOperationError(runtimeChanged, retErr) }()
	releaseLock, err := e.lockApply(ctx)
	if err != nil {
		return err
	}
	defer func() {
		appendFailure(&retErr, "release apply locks", releaseLock())
	}()
	cfg, err := e.refreshForApply(ctx)
	if err != nil {
		return err
	}

	rev, err := e.Store.GetConfigRevision(ctx, revisionID)
	if err != nil {
		return err
	}
	if len(rev.HAProxySHA256) < 12 {
		return fmt.Errorf("invalid stored revision hash")
	}

	manifestRevision := filepath.Base(filepath.Clean(rev.ContentPath)) == "manifest.json"
	var targetExtra []string
	if manifestRevision {
		targetManifest, err := readAndVerifyArtifactManifest(rev.ContentPath)
		if err != nil {
			return fmt.Errorf("revision artifact manifest invalid: %w", err)
		}
		if !strings.EqualFold(targetManifest.ConfigSHA256, rev.HAProxySHA256) {
			return fmt.Errorf("revision artifact manifest config checksum mismatch")
		}
		targetExtra = artifactManifestPaths(targetManifest)
	}

	cfgPath := haproxy.LiveCfgPath(e.StateDir, cfg.HAProxyConfigPath)
	// A historical revision can write paths no longer present in settings.
	// Snapshot their current contents (or absence) before restoring any file.
	tx, err := e.beginArtifactTransaction(cfg, targetExtra...)
	if err != nil {
		return fmt.Errorf("snapshot current HAProxy artifacts: %w", err)
	}
	defer func() { _ = tx.remove() }()

	skipReload := envflag.Enabled("EASY_WAF_SKIP_RELOAD")
	promoted := false
	var revisionSnapshot *artifactSnapshot
	defer func() {
		if retErr == nil {
			return
		}
		if runtimeChanged {
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

	if manifestRevision {
		currentManaged, err := e.managedArtifactPaths(cfg, targetExtra)
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
		if !envflag.Enabled("EASY_WAF_SKIP_VALIDATE") {
			if err := apply.Validate(ctx, cfg.HAProxyBinary, staging); err != nil {
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
	if !envflag.Enabled("EASY_WAF_SKIP_VALIDATE") {
		if err := apply.Validate(ctx, cfg.HAProxyBinary, cfgPath); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	revisionSnapshot, err = e.createRevisionSnapshot(cfg, got, targetExtra)
	if err != nil {
		return fmt.Errorf("snapshot rollback revision: %w", err)
	}
	if err := e.markReloadPending(); err != nil {
		return fmt.Errorf("mark reload pending: %w", err)
	}
	certs := e.certsBeforeLoad()
	if !skipReload {
		if err := apply.ReloadHAProxy(ctx); err != nil {
			return err
		}
		runtimeChanged = true
	}
	e.saveLoadedCerts(certs)
	e.clearReloadPending()
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
		return fmt.Errorf("record rollback revision and audit: %w", err)
	}
	return nil
}
