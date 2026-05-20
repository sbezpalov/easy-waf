package nft

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		HelperReady: runner.HelperInstalled(),
	}
	if b, err := os.ReadFile(RulesPath); err == nil {
		st.Ruleset = string(b)
	}
	if runner.HelperInstalled() {
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
