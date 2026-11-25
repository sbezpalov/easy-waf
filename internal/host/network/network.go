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
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/hostname"); err == nil {
		out.Hostname = strings.TrimSpace(string(b))
	}
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", "link", "show"); err == nil {
		_ = json.Unmarshal(b, &out.Links)
	}
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", "addr", "show"); err == nil {
		_ = json.Unmarshal(b, &out.Addresses)
	}
	if b, err := runner.Run(ctx, 15*time.Second, "/usr/bin/ip", "-j", "route", "show"); err == nil {
		_ = json.Unmarshal(b, &out.Routes)
	}
	if b, err := runner.Run(ctx, 10*time.Second, "/usr/bin/resolvectl", "status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DNS Servers:") {
				rest := strings.TrimPrefix(line, "DNS Servers:")
				out.DNS = append(out.DNS, strings.Fields(rest)...)
			}
		}
	}
	if b, err := runner.Run(ctx, 10*time.Second, "/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		out.NTP = strings.TrimSpace(string(b))
	}
	out.Netplan, out.ManagedNetplanState = readNetplanFiles("/etc/netplan")
	return out, nil
}

func readNetplanFiles(dir string) ([]NetplanFile, string) {
	managed := filepath.Join(dir, "99-easy-waf.yaml")
	state := "unavailable"
	if _, err := os.Lstat(managed); os.IsNotExist(err) {
		state = "absent"
	}
	var files []NetplanFile
	matches, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			if p == managed {
				state = "unavailable"
			}
			continue
		}
		files = append(files, NetplanFile{Path: p, Content: string(b)})
		if p == managed {
			state = "readable"
		}
	}
	return files, state
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
