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
)

// Overview is host network state for the API.
type Overview struct {
	Links     []json.RawMessage `json:"links"`
	Addresses []json.RawMessage `json:"addresses"`
	Routes    []json.RawMessage `json:"routes,omitempty"`
	Hostname  string            `json:"hostname"`
	DNS       []string          `json:"dns,omitempty"`
	NTP       string            `json:"ntp_synced,omitempty"`
	Netplan   []NetplanFile     `json:"netplan_files,omitempty"`
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
	matches, _ := filepath.Glob("/etc/netplan/*.yaml")
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out.Netplan = append(out.Netplan, NetplanFile{Path: p, Content: string(b)})
	}
	return out, nil
}

// ApplyNetplan stages YAML and applies via the privileged helper.
func ApplyNetplan(ctx context.Context, yaml string) error {
	yaml = strings.TrimSpace(yaml)
	if yaml == "" {
		return os.ErrInvalid
	}
	dir := "/var/lib/easy-waf/staging"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	staged := filepath.Join(dir, "99-easy-waf.yaml")
	if err := os.WriteFile(staged, []byte(yaml+"\n"), 0o600); err != nil {
		return err
	}
	_, err := runner.Privileged(ctx, "netplan-install", staged)
	return err
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
	dir := "/var/lib/easy-waf/staging"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", time.Time{}, err
	}
	staged := filepath.Join(dir, "netplan-"+tok+".yaml")
	if err := os.WriteFile(staged, []byte(yaml+"\n"), 0o600); err != nil {
		return "", time.Time{}, err
	}
	if _, err := runner.Privileged(ctx, "netplan-apply-confirm", staged, strconv.Itoa(timeoutSec), tok); err != nil {
		return "", time.Time{}, err
	}
	return tok, time.Now().UTC().Add(time.Duration(timeoutSec) * time.Second), nil
}

// CommitNetplan cancels the rollback timer and removes the backup for token.
func CommitNetplan(ctx context.Context, token string) error {
	if !rollback.ValidToken(token) {
		return os.ErrInvalid
	}
	_, err := runner.Privileged(ctx, "netplan-commit", token)
	return err
}
