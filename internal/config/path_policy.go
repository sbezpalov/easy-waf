// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	// PathModeDefault keeps profile block lists and restricted paths, and adds no allowlist.
	PathModeDefault = "default"
	// PathModeAllowlist publishes only the listed prefixes. Everything else is 404.
	PathModeAllowlist = "allowlist"

	// MinTimeoutSec and MaxTimeoutSec bound timeout client / timeout server overrides.
	// The upper bound is 24h, which covers a quiet SSE stream without an unbounded hold.
	MinTimeoutSec = 1
	MaxTimeoutSec = 24 * 60 * 60

	maxAllowPaths     = 32
	maxPathRules      = 8
	maxHeaderNameLen  = 64
	maxValuePrefixLen = 128
	minEdgeTokenLen   = 16
	maxEdgeTokenLen   = 256
	maxRatePer10s     = 1_000_000
)

// PathPolicy is per-application exposure on top of profile block lists and restricted paths.
//
// Mode "" means unset. The ha-mcp profile treats an unset policy as its preset.
// Mode "default" is an explicit choice to publish every path the block lists allow.
type PathPolicy struct {
	Mode string `json:"mode,omitempty"`
	// Allow lists URL prefixes published when Mode is allowlist.
	// A prefix matches that path and everything under it, not a longer sibling
	// (/api/mcp matches /api/mcp and /api/mcp/assist, not /api/mcp-other).
	Allow []string `json:"allow,omitempty"`
	// ClientTimeoutSec and ServerTimeoutSec extend inactivity timeouts for every
	// request to this application. Zero keeps the frontend default (client) and
	// the profile timeout (server). Per-rule values override these on a match,
	// and the longest matching prefix wins.
	ClientTimeoutSec int        `json:"client_timeout_sec,omitempty"`
	ServerTimeoutSec int        `json:"server_timeout_sec,omitempty"`
	Rules            []PathRule `json:"rules,omitempty"`
}

// PathRule is one prefix with optional header, timeout and rate-limit requirements.
// RatePer10s counts requests in a 10 second window, the same unit as the
// application stick-table burst. The longest matching prefix owns the counter
// when several rules overlap.
type PathRule struct {
	PathPrefix         string `json:"path_prefix"`
	RequireHeader      string `json:"require_header,omitempty"`
	RequireValuePrefix string `json:"require_value_prefix,omitempty"`
	// EdgeTokenHeader is checked against a file under the state directory.
	// The file is group-readable by HAProxy. The value is never stored here.
	EdgeTokenHeader string `json:"edge_token_header,omitempty"`
	// EdgeTokenConfigured reports that a token file exists. Clients cannot turn
	// this on by sending it; the API sets it after writing the file.
	EdgeTokenConfigured bool `json:"edge_token_configured,omitempty"`
	// EdgeToken is write-only. MarshalJSON drops it so it cannot reach the
	// database, an audit clone, or a GET response.
	EdgeToken string `json:"edge_token,omitempty"`
	// ClearEdgeToken removes a previously stored token for this rule.
	ClearEdgeToken   bool `json:"clear_edge_token,omitempty"`
	ClientTimeoutSec int  `json:"client_timeout_sec,omitempty"`
	ServerTimeoutSec int  `json:"server_timeout_sec,omitempty"`
	RatePer10s       int  `json:"rate_per_10s,omitempty"`
}

// MarshalJSON omits write-only secret fields.
func (p PathPolicy) MarshalJSON() ([]byte, error) {
	type alias PathPolicy
	cp := p
	cp.Rules = append([]PathRule(nil), p.Rules...)
	for i := range cp.Rules {
		cp.Rules[i].EdgeToken = ""
		cp.Rules[i].ClearEdgeToken = false
	}
	return json.Marshal(alias(cp))
}

// PathPolicyUnset reports that the client did not choose a policy.
func PathPolicyUnset(p PathPolicy) bool {
	return strings.TrimSpace(p.Mode) == "" &&
		len(p.Allow) == 0 &&
		len(p.Rules) == 0 &&
		p.ClientTimeoutSec == 0 &&
		p.ServerTimeoutSec == 0
}

// ClonePathPolicy returns a deep copy. The write-only token is not copied:
// callers that still need it must read it before cloning.
func ClonePathPolicy(p *PathPolicy) *PathPolicy {
	if p == nil {
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var out PathPolicy
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}

// NormalizePathPolicy trims and canonicalises mode, prefixes and header names.
func NormalizePathPolicy(p *PathPolicy) {
	if p == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "", PathModeDefault:
		if strings.TrimSpace(p.Mode) == "" {
			p.Mode = ""
		} else {
			p.Mode = PathModeDefault
		}
	case PathModeAllowlist:
		p.Mode = PathModeAllowlist
	}
	p.Allow = normalizePathList(p.Allow)
	for i := range p.Rules {
		r := &p.Rules[i]
		r.PathPrefix = strings.TrimSpace(r.PathPrefix)
		r.RequireHeader = canonicalHeader(r.RequireHeader)
		r.EdgeTokenHeader = canonicalHeader(r.EdgeTokenHeader)
		r.EdgeToken = strings.TrimSpace(r.EdgeToken)
	}
}

func normalizePathList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalHeader(name string) string {
	return strings.TrimSpace(name)
}

// ValidatePathPolicy rejects values that would break or weaken the generated config.
func ValidatePathPolicy(p *PathPolicy) error {
	if p == nil {
		return nil
	}
	NormalizePathPolicy(p)
	switch p.Mode {
	case "", PathModeDefault, PathModeAllowlist:
	default:
		return fmt.Errorf("path_policy.mode must be %q or %q", PathModeDefault, PathModeAllowlist)
	}
	if err := validateTimeout("path_policy.client_timeout_sec", p.ClientTimeoutSec); err != nil {
		return err
	}
	if err := validateTimeout("path_policy.server_timeout_sec", p.ServerTimeoutSec); err != nil {
		return err
	}
	if p.Mode == PathModeAllowlist && len(p.Allow) == 0 {
		return fmt.Errorf("path_policy.allow must list at least one path when mode is allowlist")
	}
	if len(p.Allow) > maxAllowPaths {
		return fmt.Errorf("path_policy.allow allows at most %d entries", maxAllowPaths)
	}
	for i, path := range p.Allow {
		if err := validateExposurePath(fmt.Sprintf("path_policy.allow[%d]", i), path); err != nil {
			return err
		}
	}
	if len(p.Rules) > maxPathRules {
		return fmt.Errorf("path_policy.rules allows at most %d entries", maxPathRules)
	}
	seenEdge := map[string]struct{}{}
	for i, r := range p.Rules {
		field := fmt.Sprintf("path_policy.rules[%d]", i)
		if err := validateExposurePath(field+".path_prefix", r.PathPrefix); err != nil {
			return err
		}
		if err := validateHeaderName(field+".require_header", r.RequireHeader, false); err != nil {
			return err
		}
		if err := validateHeaderName(field+".edge_token_header", r.EdgeTokenHeader, false); err != nil {
			return err
		}
		if r.RequireValuePrefix != "" && r.RequireHeader == "" {
			return fmt.Errorf("%s.require_value_prefix requires require_header", field)
		}
		if err := validateValuePrefix(field+".require_value_prefix", r.RequireValuePrefix); err != nil {
			return err
		}
		if err := validateTimeout(field+".client_timeout_sec", r.ClientTimeoutSec); err != nil {
			return err
		}
		if err := validateTimeout(field+".server_timeout_sec", r.ServerTimeoutSec); err != nil {
			return err
		}
		if r.RatePer10s < 0 || r.RatePer10s > maxRatePer10s {
			return fmt.Errorf("%s.rate_per_10s must be between 1 and %d", field, maxRatePer10s)
		}
		if r.EdgeToken != "" {
			if r.EdgeTokenHeader == "" {
				return fmt.Errorf("%s.edge_token requires edge_token_header", field)
			}
			if err := validateEdgeToken(r.EdgeToken); err != nil {
				return fmt.Errorf("%s.edge_token: %w", field, err)
			}
		}
		if r.EdgeTokenHeader != "" {
			key := strings.ToLower(r.PathPrefix) + "\n" + strings.ToLower(r.EdgeTokenHeader)
			if _, ok := seenEdge[key]; ok {
				return fmt.Errorf("%s repeats edge_token_header %s on the same path", field, r.EdgeTokenHeader)
			}
			seenEdge[key] = struct{}{}
		}
	}
	return nil
}

func validateTimeout(field string, sec int) error {
	if sec == 0 {
		return nil
	}
	if sec < MinTimeoutSec || sec > MaxTimeoutSec {
		return fmt.Errorf("%s must be between %d and %d seconds", field, MinTimeoutSec, MaxTimeoutSec)
	}
	return nil
}

func validateExposurePath(field, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if path == "/" {
		return fmt.Errorf("%s must be more specific than /", field)
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "..") || strings.Contains(lower, "%2e") {
		return fmt.Errorf("%s must be a specific path prefix", field)
	}
	if strings.ContainsAny(path, "$'\"#`\\ \t\r\n") {
		return fmt.Errorf("%s contains a character HAProxy would treat specially", field)
	}
	return ValidateHAProxyPath(field, path)
}

func validateHeaderName(field, name string, required bool) error {
	if name == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if len(name) > maxHeaderNameLen {
		return fmt.Errorf("%s is too long", field)
	}
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("%s must contain only letters, digits and hyphen", field)
	}
	return nil
}

func validateValuePrefix(field, prefix string) error {
	if prefix == "" {
		return nil
	}
	if len(prefix) > maxValuePrefixLen {
		return fmt.Errorf("%s is too long", field)
	}
	for _, r := range prefix {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return fmt.Errorf("%s must be printable ASCII", field)
		}
	}
	if strings.ContainsAny(prefix, "\"\\$#`\r\n") {
		return fmt.Errorf("%s contains a character HAProxy would treat specially", field)
	}
	return nil
}

func validateEdgeToken(token string) error {
	if len(token) < minEdgeTokenLen || len(token) > maxEdgeTokenLen {
		return fmt.Errorf("must be %d-%d characters", minEdgeTokenLen, maxEdgeTokenLen)
	}
	for _, r := range token {
		if r == '\n' || r == '\r' || r == 0 {
			return fmt.Errorf("must not contain a line break")
		}
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return fmt.Errorf("must be printable ASCII")
		}
	}
	return nil
}

// EdgeTokenFile is the on-disk secret for one rule. The name is a hash of the
// path and header so reordering rules does not move the file.
func EdgeTokenFile(stateDir, appID, pathPrefix, header string) (string, error) {
	if err := ValidateResourceID("application", appID); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(pathPrefix) + "\n" + strings.ToLower(strings.TrimSpace(header))))
	name := hex.EncodeToString(sum[:8]) + ".token"
	dir := filepath.Join(stateDir, "secrets", "edge-tokens", appID)
	// This path is both used for local file I/O and rendered into haproxy.cfg.
	// Forward slashes work on Windows too and keep the generated Linux config
	// independent of the development host.
	return filepath.ToSlash(filepath.Join(dir, name)), nil
}

// SyncEdgeTokens writes or removes token files for policy and clears write-only
// fields. restore puts the application's token directory back; call it when the
// database change is undone. A nil policy is a no-op.
func SyncEdgeTokens(stateDir, appID string, policy, previous *PathPolicy) (restore func() error, err error) {
	noop := func() error { return nil }
	if policy == nil {
		return noop, nil
	}
	NormalizePathPolicy(policy)
	needsFile := edgeTokensInUse(policy) || edgeTokensInUse(previous)
	if !needsFile {
		for i := range policy.Rules {
			policy.Rules[i].EdgeToken = ""
			policy.Rules[i].ClearEdgeToken = false
			policy.Rules[i].EdgeTokenConfigured = false
		}
		return noop, nil
	}
	if strings.TrimSpace(stateDir) == "" {
		return nil, fmt.Errorf("edge token requires a state directory")
	}
	if err := ValidateResourceID("application", appID); err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, "secrets", "edge-tokens", appID)
	snap, err := snapshotTokenDir(dir)
	if err != nil {
		return nil, err
	}
	keep := map[string]struct{}{}
	for i := range policy.Rules {
		r := &policy.Rules[i]
		if r.EdgeTokenHeader == "" {
			r.EdgeTokenConfigured = false
			r.EdgeToken = ""
			r.ClearEdgeToken = false
			continue
		}
		file, err := EdgeTokenFile(stateDir, appID, r.PathPrefix, r.EdgeTokenHeader)
		if err != nil {
			_ = restoreTokenDir(dir, snap)
			return nil, err
		}
		switch {
		case r.EdgeToken != "":
			if err := validateEdgeToken(r.EdgeToken); err != nil {
				_ = restoreTokenDir(dir, snap)
				return nil, fmt.Errorf("path_policy.rules[%d].edge_token: %w", i, err)
			}
			if err := writeEdgeToken(file, r.EdgeToken); err != nil {
				_ = restoreTokenDir(dir, snap)
				return nil, fmt.Errorf("path_policy.rules[%d]: cannot store edge token", i)
			}
			r.EdgeTokenConfigured = true
		case r.ClearEdgeToken:
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				_ = restoreTokenDir(dir, snap)
				return nil, fmt.Errorf("path_policy.rules[%d]: cannot remove edge token", i)
			}
			r.EdgeTokenConfigured = false
		default:
			r.EdgeTokenConfigured = tokenFileReady(file) && previousEdgeConfigured(previous, r.PathPrefix, r.EdgeTokenHeader)
		}
		r.EdgeToken = ""
		r.ClearEdgeToken = false
		if r.EdgeTokenConfigured {
			keep[file] = struct{}{}
		} else if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			_ = restoreTokenDir(dir, snap)
			return nil, fmt.Errorf("path_policy.rules[%d]: cannot remove edge token", i)
		}
	}
	if err := removeUnkeptTokens(dir, keep); err != nil {
		_ = restoreTokenDir(dir, snap)
		return nil, err
	}
	return func() error { return restoreTokenDir(dir, snap) }, nil
}

func edgeTokensInUse(p *PathPolicy) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Rules {
		if r.EdgeTokenHeader != "" || r.EdgeToken != "" || r.ClearEdgeToken || r.EdgeTokenConfigured {
			return true
		}
	}
	return false
}

func previousEdgeConfigured(previous *PathPolicy, pathPrefix, header string) bool {
	if previous == nil {
		return false
	}
	for _, r := range previous.Rules {
		if strings.TrimSpace(r.PathPrefix) == strings.TrimSpace(pathPrefix) && strings.EqualFold(r.EdgeTokenHeader, header) && r.EdgeTokenConfigured {
			return true
		}
	}
	return false
}

func tokenFileReady(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}

func writeEdgeToken(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// Group-readable so the haproxy user, which is in the easy-waf group, can
	// compare the header. The value is not world-readable and is not copied
	// into haproxy.cfg.
	// 0640: the haproxy user is in the easy-waf group and must read the token.
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o640); err != nil { //nolint:gosec // group-readable for haproxy, not world-readable
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o640)
}

func snapshotTokenDir(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

func restoreTokenDir(dir string, snap map[string][]byte) error {
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(snap) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for name, body := range snap {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o640); err != nil { //nolint:gosec // restored token stays group-readable for haproxy
			return err
		}
	}
	return nil
}

func removeUnkeptTokens(dir string, keep map[string]struct{}) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if _, ok := keep[path]; ok {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
