// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/rollback"
	"github.com/easy-waf/easy-waf/internal/host/runner"
	"github.com/easy-waf/easy-waf/internal/host/staging"
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
	return staging.WithFile("easy-waf-*.nft", []byte(content+"\n"), func(path string) error {
		if _, err := runner.Run(ctx, 30*time.Second, "/usr/sbin/nft", "-c", "-f", path); err != nil {
			return fmt.Errorf("nft -c: %w", err)
		}
		_, err := runner.Privileged(ctx, "nft-install", path)
		return err
	})
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
	var deadline time.Time
	if err := staging.WithFile("easy-waf-*.nft", []byte(content+"\n"), func(path string) error {
		if _, err := runner.Run(ctx, 30*time.Second, "/usr/sbin/nft", "-c", "-f", path); err != nil {
			return fmt.Errorf("nft -c: %w", err)
		}
		var err error
		deadline, err = runner.PrivilegedWithRollback(ctx, time.Duration(timeoutSec)*time.Second, "nft-apply-confirm", path, strconv.Itoa(timeoutSec), tok)
		return err
	}); err != nil {
		return "", time.Time{}, err
	}
	return tok, deadline, nil
}

// CommitRuleset cancels the rollback timer and removes the backup for token.
func CommitRuleset(ctx context.Context, token string) error {
	if !rollback.ValidToken(token) {
		return os.ErrInvalid
	}
	_, err := runner.Privileged(ctx, "nft-commit", token)
	return err
}
