// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/rollback"
	"github.com/easy-waf/easy-waf/internal/host/runner"
)

const RulesPath = "/etc/nftables/easy-waf.nft"

// Status is the host firewall snapshot for the API.
type Status struct {
	RulesPath   string `json:"rules_path"`
	Ruleset     string `json:"ruleset,omitempty"`
	HelperReady bool   `json:"helper_ready"`
}

// GetStatus returns the managed ruleset file and live ruleset when possible.
func GetStatus(ctx context.Context) (Status, error) {
	st := Status{
		RulesPath:   RulesPath,
		HelperReady: runner.BrokerAvailable(),
	}
	if b, err := os.ReadFile(RulesPath); err == nil {
		st.Ruleset = string(b)
	}
	if runner.BrokerAvailable() {
		out, err := runner.Privileged(ctx, "nft-list")
		if err == nil {
			st.Ruleset = string(out)
		}
	}
	return st, nil
}

// Apply reloads the managed ruleset via the privileged helper.
func Apply(ctx context.Context) error {
	_, err := runner.Privileged(ctx, "nft-apply")
	return err
}

// PutRuleset stages rules, validates, installs to RulesPath, and applies.
func PutRuleset(ctx context.Context, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return os.ErrInvalid
	}
	dir := "/var/lib/easy-waf/staging"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, "easy-waf.nft")
	if err := os.WriteFile(tmpPath, []byte(content+"\n"), 0o600); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, 30*time.Second, "/usr/sbin/nft", "-c", "-f", tmpPath); err != nil {
		return fmt.Errorf("nft -c: %w", err)
	}
	_, err := runner.Privileged(ctx, "nft-install", tmpPath)
	return err
}

// ApplyRulesetWithRollback stages rules, validates, applies via privileged helper with systemd-run revert.
func ApplyRulesetWithRollback(ctx context.Context, content string, timeoutSec int) (token string, expiresAt time.Time, err error) {
	content = strings.TrimSpace(content)
	if content == "" {
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
	staged := filepath.Join(dir, "easy-waf-"+tok+".nft")
	if err := os.WriteFile(staged, []byte(content+"\n"), 0o600); err != nil {
		return "", time.Time{}, err
	}
	if _, err := runner.Run(ctx, 30*time.Second, "/usr/sbin/nft", "-c", "-f", staged); err != nil {
		return "", time.Time{}, fmt.Errorf("nft -c: %w", err)
	}
	if _, err := runner.Privileged(ctx, "nft-apply-confirm", staged, strconv.Itoa(timeoutSec), tok); err != nil {
		return "", time.Time{}, err
	}
	return tok, time.Now().UTC().Add(time.Duration(timeoutSec) * time.Second), nil
}

// CommitRuleset cancels the rollback timer and removes the backup for token.
func CommitRuleset(ctx context.Context, token string) error {
	if !rollback.ValidToken(token) {
		return os.ErrInvalid
	}
	_, err := runner.Privileged(ctx, "nft-commit", token)
	return err
}
