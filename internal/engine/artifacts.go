// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/blockedua"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/geoip"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/ipwl"
)

const artifactManifestVersion = 1

type artifactManifestFile struct {
	Path       string `json:"path"`
	BackupPath string `json:"backup_path"`
	SHA256     string `json:"sha256"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
}

type artifactManifest struct {
	Version      int                    `json:"version"`
	CreatedAt    time.Time              `json:"created_at"`
	ConfigPath   string                 `json:"config_path"`
	ConfigSHA256 string                 `json:"config_sha256"`
	ManagedFiles []artifactManifestFile `json:"managed_files"`
}

type artifactSnapshot struct {
	Dir          string
	ManifestPath string
	Manifest     artifactManifest
}

type artifactTransaction struct {
	engine *Engine
	// cfg is the settings snapshot the transaction started with, so the set of
	// managed paths cannot shift under it.
	cfg           config.GlobalSettings
	snapshot      *artifactSnapshot
	managedBefore []string
}

func normalizeArtifactPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func artifactPathKey(path string) string {
	path = normalizeArtifactPath(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func sameArtifactPath(a, b string) bool {
	return artifactPathKey(a) == artifactPathKey(b)
}

func appendUniquePath(paths *[]string, seen map[string]struct{}, path string) {
	path = normalizeArtifactPath(path)
	if path == "" {
		return
	}
	key := artifactPathKey(path)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*paths = append(*paths, path)
}

func (e *Engine) managedArtifactPaths(cfg config.GlobalSettings, extra []string) ([]string, error) {
	_, _, crtListPath := haproxy.Paths(e.StateDir)
	cfgPath := haproxy.LiveCfgPath(e.StateDir, cfg.HAProxyConfigPath)

	ipblPath := strings.TrimSpace(cfg.IPBlacklistMapPath)
	if ipblPath == "" {
		ipblPath = filepath.Join(e.StateDir, "haproxy", "ip_blacklist.map")
	}

	paths := make([]string, 0, 8+len(extra))
	seen := make(map[string]struct{}, cap(paths))
	for _, path := range []string{
		cfgPath,
		crtListPath,
		ipblPath,
		ipwl.MapPath(cfg, e.StateDir),
		blockedua.MapPath(cfg, e.StateDir),
		geoip.EnforceMapPath(cfg, e.StateDir),
	} {
		appendUniquePath(&paths, seen, path)
	}
	for _, path := range extra {
		appendUniquePath(&paths, seen, path)
	}

	perAppPattern := filepath.Join(e.StateDir, "haproxy", "geoip_app_*.map")
	perAppPaths, err := filepath.Glob(perAppPattern)
	if err != nil {
		return nil, fmt.Errorf("list per-app GeoIP maps: %w", err)
	}
	for _, path := range perAppPaths {
		appendUniquePath(&paths, seen, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func copyFileAndHash(src, dst string, mode os.FileMode) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), in)
	closeErr := out.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func hashFile(path string) (string, int64, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	h := sha256.New()
	n, err := io.Copy(h, in)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	if mode.Perm() == 0 {
		mode = 0o640
	}
	// HAProxy reads every managed artifact as the haproxy user through group
	// easy-waf. Revisions snapshotted before the maps became 0640 recorded
	// 0600; restoring that would leave HAProxy unable to read them.
	mode |= 0o040
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if _, _, err := copyFileAndHash(src, tmp, mode.Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeArtifactSnapshot(
	snapshotDir string,
	paths []string,
	configPath string,
) (artifactManifest, error) {
	configPath = normalizeArtifactPath(configPath)
	filesDir := filepath.Join(snapshotDir, "files")
	if err := os.MkdirAll(filesDir, 0o750); err != nil {
		return artifactManifest{}, err
	}
	manifest := artifactManifest{
		Version:      artifactManifestVersion,
		CreatedAt:    time.Now().UTC(),
		ConfigPath:   configPath,
		ManagedFiles: make([]artifactManifestFile, 0, len(paths)),
	}
	for _, path := range paths {
		path = normalizeArtifactPath(path)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return artifactManifest{}, fmt.Errorf("stat managed artifact %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return artifactManifest{}, fmt.Errorf("managed artifact is not a regular file: %s", path)
		}
		backupRel := filepath.ToSlash(filepath.Join("files", fmt.Sprintf("%06d", len(manifest.ManagedFiles))))
		backupAbs := filepath.Join(snapshotDir, filepath.FromSlash(backupRel))
		sum, size, err := copyFileAndHash(path, backupAbs, info.Mode().Perm())
		if err != nil {
			return artifactManifest{}, fmt.Errorf("snapshot managed artifact %s: %w", path, err)
		}
		manifest.ManagedFiles = append(manifest.ManagedFiles, artifactManifestFile{
			Path:       path,
			BackupPath: backupRel,
			SHA256:     sum,
			Mode:       uint32(info.Mode().Perm()),
			Size:       size,
		})
		if sameArtifactPath(path, configPath) {
			manifest.ConfigSHA256 = sum
		}
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return artifactManifest{}, err
	}
	body = append(body, '\n')
	if err := apply.WriteAtomic(filepath.Join(snapshotDir, "manifest.json"), body, 0o640); err != nil {
		return artifactManifest{}, err
	}
	return manifest, nil
}

func cleanBackupPath(snapshotDir, backupRel string) (string, error) {
	if filepath.IsAbs(backupRel) {
		return "", fmt.Errorf("absolute backup path in artifact manifest")
	}
	clean := filepath.Clean(filepath.FromSlash(backupRel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid backup path in artifact manifest: %q", backupRel)
	}
	abs := filepath.Join(snapshotDir, clean)
	rel, err := filepath.Rel(snapshotDir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backup path escapes artifact snapshot: %q", backupRel)
	}
	return abs, nil
}

func readAndVerifyArtifactManifest(manifestPath string) (artifactManifest, error) {
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		return artifactManifest{}, err
	}
	var manifest artifactManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return artifactManifest{}, fmt.Errorf("decode artifact manifest: %w", err)
	}
	if manifest.Version != artifactManifestVersion {
		return artifactManifest{}, fmt.Errorf("unsupported artifact manifest version %d", manifest.Version)
	}
	snapshotDir := filepath.Dir(manifestPath)
	seen := make(map[string]struct{}, len(manifest.ManagedFiles))
	for _, file := range manifest.ManagedFiles {
		path := normalizeArtifactPath(file.Path)
		if path == "" {
			return artifactManifest{}, fmt.Errorf("empty managed artifact path")
		}
		key := artifactPathKey(path)
		if _, ok := seen[key]; ok {
			return artifactManifest{}, fmt.Errorf("duplicate managed artifact path: %s", path)
		}
		seen[key] = struct{}{}
		backupAbs, err := cleanBackupPath(snapshotDir, file.BackupPath)
		if err != nil {
			return artifactManifest{}, err
		}
		info, err := os.Stat(backupAbs)
		if err != nil {
			return artifactManifest{}, fmt.Errorf("stat artifact backup %s: %w", backupAbs, err)
		}
		if !info.Mode().IsRegular() || info.Size() != file.Size {
			return artifactManifest{}, fmt.Errorf("artifact backup size/type mismatch: %s", backupAbs)
		}
		sum, _, err := hashFile(backupAbs)
		if err != nil {
			return artifactManifest{}, fmt.Errorf("verify artifact backup %s: %w", backupAbs, err)
		}
		if !strings.EqualFold(sum, file.SHA256) {
			return artifactManifest{}, fmt.Errorf("artifact backup checksum mismatch: %s", backupAbs)
		}
	}
	return manifest, nil
}

func artifactManifestPaths(manifest artifactManifest) []string {
	paths := make([]string, 0, len(manifest.ManagedFiles))
	for _, file := range manifest.ManagedFiles {
		paths = append(paths, normalizeArtifactPath(file.Path))
	}
	return paths
}

func manifestFileForPath(manifest artifactManifest, path string) (artifactManifestFile, bool) {
	path = normalizeArtifactPath(path)
	for _, file := range manifest.ManagedFiles {
		if sameArtifactPath(file.Path, path) {
			return file, true
		}
	}
	return artifactManifestFile{}, false
}

func restoreArtifactManifest(
	manifestPath string,
	currentManaged []string,
	currentConfigPath string,
) (artifactManifest, error) {
	manifest, err := readAndVerifyArtifactManifest(manifestPath)
	if err != nil {
		return artifactManifest{}, err
	}
	targetSet := make(map[string]struct{}, len(manifest.ManagedFiles))
	for _, file := range manifest.ManagedFiles {
		targetSet[artifactPathKey(file.Path)] = struct{}{}
	}
	for _, path := range currentManaged {
		path = normalizeArtifactPath(path)
		if path == "" {
			continue
		}
		if _, keep := targetSet[artifactPathKey(path)]; keep {
			continue
		}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return artifactManifest{}, fmt.Errorf("stat obsolete managed artifact %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return artifactManifest{}, fmt.Errorf("obsolete managed artifact is not a regular file: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return artifactManifest{}, fmt.Errorf("remove obsolete managed artifact %s: %w", path, err)
		}
	}

	files := append([]artifactManifestFile(nil), manifest.ManagedFiles...)
	sort.SliceStable(files, func(i, j int) bool {
		iConfig := sameArtifactPath(files[i].Path, manifest.ConfigPath)
		jConfig := sameArtifactPath(files[j].Path, manifest.ConfigPath)
		if iConfig != jConfig {
			return !iConfig
		}
		return files[i].Path < files[j].Path
	})
	snapshotDir := filepath.Dir(manifestPath)
	for _, file := range files {
		backupAbs, err := cleanBackupPath(snapshotDir, file.BackupPath)
		if err != nil {
			return artifactManifest{}, err
		}
		if err := copyFileAtomic(backupAbs, file.Path, os.FileMode(file.Mode)); err != nil {
			return artifactManifest{}, fmt.Errorf("restore managed artifact %s: %w", file.Path, err)
		}
	}

	currentConfigPath = normalizeArtifactPath(currentConfigPath)
	if currentConfigPath != "" && !sameArtifactPath(currentConfigPath, manifest.ConfigPath) {
		configFile, ok := manifestFileForPath(manifest, manifest.ConfigPath)
		if !ok {
			return artifactManifest{}, fmt.Errorf("artifact manifest does not contain its config path %s", manifest.ConfigPath)
		}
		backupAbs, err := cleanBackupPath(snapshotDir, configFile.BackupPath)
		if err != nil {
			return artifactManifest{}, err
		}
		if err := copyFileAtomic(backupAbs, currentConfigPath, os.FileMode(configFile.Mode)); err != nil {
			return artifactManifest{}, fmt.Errorf("restore config at current path %s: %w", currentConfigPath, err)
		}
	}
	return manifest, nil
}

func (e *Engine) newArtifactSnapshot(cfg config.GlobalSettings, kind string, extra []string) (*artifactSnapshot, error) {
	paths, err := e.managedArtifactPaths(cfg, extra)
	if err != nil {
		return nil, err
	}
	revisionsDir := filepath.Join(e.StateDir, "revisions")
	if err := os.MkdirAll(revisionsDir, 0o750); err != nil {
		return nil, err
	}
	dir := filepath.Join(revisionsDir, kind+"-"+uuid.NewString())
	cfgPath := haproxy.LiveCfgPath(e.StateDir, cfg.HAProxyConfigPath)
	manifest, err := writeArtifactSnapshot(dir, paths, cfgPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &artifactSnapshot{
		Dir:          dir,
		ManifestPath: filepath.Join(dir, "manifest.json"),
		Manifest:     manifest,
	}, nil
}

func (s *artifactSnapshot) remove() error {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return nil
	}
	return os.RemoveAll(s.Dir)
}

func (s *artifactSnapshot) hasFile(path string) bool {
	if s == nil {
		return false
	}
	_, ok := manifestFileForPath(s.Manifest, path)
	return ok
}

func (e *Engine) beginArtifactTransaction(cfg config.GlobalSettings) (*artifactTransaction, error) {
	managed, err := e.managedArtifactPaths(cfg, nil)
	if err != nil {
		return nil, err
	}
	snapshot, err := e.newArtifactSnapshot(cfg, ".apply-before", nil)
	if err != nil {
		return nil, err
	}
	return &artifactTransaction{
		engine:        e,
		cfg:           cfg,
		snapshot:      snapshot,
		managedBefore: managed,
	}, nil
}

func (t *artifactTransaction) rollback() error {
	if t == nil || t.snapshot == nil {
		return nil
	}
	extra := append([]string(nil), t.managedBefore...)
	extra = append(extra, artifactManifestPaths(t.snapshot.Manifest)...)
	current, err := t.engine.managedArtifactPaths(t.cfg, extra)
	if err != nil {
		return err
	}
	cfgPath := haproxy.LiveCfgPath(t.engine.StateDir, t.cfg.HAProxyConfigPath)
	_, err = restoreArtifactManifest(t.snapshot.ManifestPath, current, cfgPath)
	return err
}

func (t *artifactTransaction) remove() error {
	if t == nil {
		return nil
	}
	return t.snapshot.remove()
}

func (e *Engine) createRevisionSnapshot(cfg config.GlobalSettings, sha256Hex string, extra []string) (*artifactSnapshot, error) {
	snapshot, err := e.newArtifactSnapshot(cfg, "artifacts", extra)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(snapshot.Manifest.ConfigSHA256, sha256Hex) {
		_ = snapshot.remove()
		return nil, fmt.Errorf(
			"revision config checksum mismatch: snapshot=%s rendered=%s",
			snapshot.Manifest.ConfigSHA256,
			sha256Hex,
		)
	}
	cfgPath := haproxy.LiveCfgPath(e.StateDir, cfg.HAProxyConfigPath)
	previewPath := filepath.Join(e.StateDir, "revisions", fmt.Sprintf("haproxy-%s.cfg", sha256Hex[:12]))
	if err := copyFileAtomic(cfgPath, previewPath, 0o640); err != nil {
		_ = snapshot.remove()
		return nil, err
	}
	return snapshot, nil
}

// artifactsUnchanged reports whether rendering reproduced exactly what was
// live: the new config equals the one in the pre-render snapshot, and every
// managed file on disk now (maps and crt-list, which the render rewrites in
// place) still has the hash the snapshot recorded, with none added.
func (e *Engine) artifactsUnchanged(cfg config.GlobalSettings, before *artifactSnapshot, cfgPath string, rendered []byte) (bool, error) {
	if before == nil || !before.hasFile(cfgPath) || !strings.EqualFold(before.Manifest.ConfigSHA256, sha256HexBytes(rendered)) {
		return false, nil
	}
	paths, err := e.managedArtifactPaths(cfg, nil)
	if err != nil {
		return false, err
	}
	for _, path := range paths {
		if artifactPathKey(path) == artifactPathKey(cfgPath) {
			continue
		}
		recorded, inSnapshot := manifestFileForPath(before.Manifest, path)
		sum, err := sha256HexFile(path)
		if os.IsNotExist(err) {
			if inSnapshot {
				return false, nil
			}
			continue
		}
		if err != nil {
			return false, err
		}
		if !inSnapshot || !strings.EqualFold(recorded.SHA256, sum) {
			return false, nil
		}
	}
	return true, nil
}
