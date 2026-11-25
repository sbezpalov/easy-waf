// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/rollback"
	"github.com/easy-waf/easy-waf/internal/host/runner"
	"github.com/easy-waf/easy-waf/internal/host/staging"
)

// Overview is host network state for the API.
type Overview struct {
	Links               []json.RawMessage `json:"links"`
	Addresses           []json.RawMessage `json:"addresses"`
	Routes              []json.RawMessage `json:"routes,omitempty"`
	Hostname            string            `json:"hostname"`
	DNS                 []string          `json:"dns,omitempty"`
	NTP                 string            `json:"ntp_synced,omitempty"`
	Netplan             []NetplanFile     `json:"netplan_files,omitempty"`
	ManagedNetplanState string            `json:"managed_netplan_state"`
}

type NetplanFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// GetOverview collects link/addr/route JSON from ip(8) and netplan files.
func GetOverview(ctx context.Context) (Overview, error) {
	var out Overview
	out.Hostname, _ = Hostname(ctx)
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", "link", "show"); err == nil {
		_ = json.Unmarshal(b, &out.Links)
	}
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", "addr", "show"); err == nil {
		_ = json.Unmarshal(b, &out.Addresses)
	}
	out.Routes = collectRoutes(func(family string) ([]byte, error) {
		return runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", family, "route", "show")
	})
	if b, err := runner.Run(ctx, 10*time.Second, "/usr/bin/resolvectl", "dns"); err == nil {
		out.DNS = parseResolverDNS(string(b))
	}
	if b, err := runner.Run(ctx, 10*time.Second, "/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		out.NTP = strings.TrimSpace(string(b))
	}
	out.Netplan, out.ManagedNetplanState = readNetplanFiles("/etc/netplan")
	return out, nil
}

// Hostname reads the host's configured name via hostnamed. The API runs with
// ProtectHostname and its private UTS namespace may predate a rename.
func Hostname(ctx context.Context) (string, error) {
	b, err := runner.Run(ctx, 5*time.Second, "/usr/bin/hostnamectl", "--static")
	if err == nil && strings.TrimSpace(string(b)) != "" {
		return strings.TrimSpace(string(b)), nil
	}
	b, err = runner.Run(ctx, 5*time.Second, "/usr/bin/hostnamectl", "--transient")
	return strings.TrimSpace(string(b)), err
}

func collectRoutes(readFamily func(string) ([]byte, error)) []json.RawMessage {
	var routes []json.RawMessage
	for _, family := range []string{"-4", "-6"} {
		data, err := readFamily(family)
		if err != nil {
			continue
		}
		var batch []json.RawMessage
		if json.Unmarshal(data, &batch) == nil {
			routes = append(routes, batch...)
		}
	}
	return routes
}

// resolvectl dns wraps long global and per-link lists onto indented lines.
func parseResolverDNS(output string) []string {
	var servers []string
	var inList bool
	for line := range strings.Lines(output) {
		switch {
		case strings.HasPrefix(line, "Global:"):
			line = strings.TrimPrefix(line, "Global:")
			inList = true
		case strings.HasPrefix(line, "Link "):
			_, line, inList = strings.Cut(line, "):")
		case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
			inList = false
		}
		if inList {
			servers = append(servers, strings.Fields(line)...)
		}
	}
	return servers
}

func readNetplanFiles(dir string) ([]NetplanFile, string) {
	managed := filepath.Join(dir, "99-easy-waf.yaml")
	data, err := hostspec.ReadManagedConfig(managed)
	if os.IsNotExist(err) {
		return nil, "absent"
	}
	if err != nil {
		return nil, "unavailable"
	}
	return []NetplanFile{{Path: managed, Content: data}}, "readable"
}

// ApplyNetplan stages YAML and applies via the privileged helper.
func ApplyNetplan(ctx context.Context, yaml string) error {
	yaml = strings.TrimSpace(yaml)
	if yaml == "" {
		return os.ErrInvalid
	}
	return staging.WithFile("netplan-*.yaml", []byte(yaml+"\n"), func(path string) error {
		_, err := runner.Privileged(ctx, "netplan-install", path)
		return err
	})
}

// ApplyNetplanWithRollback stages YAML and applies with a systemd-run auto-revert window.
func ApplyNetplanWithRollback(ctx context.Context, yaml string, timeoutSec int) (token string, expiresAt time.Time, err error) {
	yaml = strings.TrimSpace(yaml)
	if yaml == "" {
		return "", time.Time{}, os.ErrInvalid
	}
	timeoutSec = rollback.ClampRollbackSeconds(timeoutSec)
	tok, err := rollback.GenerateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	var deadline time.Time
	if err := staging.WithFile("netplan-*.yaml", []byte(yaml+"\n"), func(path string) error {
		var err error
		deadline, err = runner.PrivilegedWithRollback(ctx, time.Duration(timeoutSec)*time.Second, "netplan-apply-confirm", path, strconv.Itoa(timeoutSec), tok)
		return err
	}); err != nil {
		return "", time.Time{}, err
	}
	return tok, deadline, nil
}

// CommitNetplan cancels the rollback timer and removes the backup for token.
func CommitNetplan(ctx context.Context, token string) error {
	if !rollback.ValidToken(token) {
		return os.ErrInvalid
	}
	_, err := runner.Privileged(ctx, "netplan-commit", token)
	return err
}
