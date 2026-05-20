package apt

import (
	"context"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// UpdatesStatus is apt upgrade preview or result.
type UpdatesStatus struct {
	Output string `json:"output"`
}

// Update runs apt-get update.
func Update(ctx context.Context) (UpdatesStatus, error) {
	_, err := runner.Privileged(ctx, "apt-update")
	return UpdatesStatus{Output: "ok"}, err
}

// SimulateUpgrade lists upgradable packages (apt-get -s upgrade).
func SimulateUpgrade(ctx context.Context) (UpdatesStatus, error) {
	out, err := runner.Privileged(ctx, "apt-simulate")
	return UpdatesStatus{Output: string(out)}, err
}

// Upgrade runs non-interactive apt-get upgrade -y.
func Upgrade(ctx context.Context) (UpdatesStatus, error) {
	_, err := runner.Privileged(ctx, "apt-upgrade")
	if err != nil {
		return UpdatesStatus{}, err
	}
	return UpdatesStatus{Output: "upgrade finished"}, nil
}

// ListUpgradable reads /var/lib/apt/lists or runs apt list --upgradable without root.
func ListUpgradable(ctx context.Context) (UpdatesStatus, error) {
	out, err := runner.Run(ctx, 90*time.Second, "/usr/bin/apt", "list", "--upgradable")
	if err != nil {
		// fallback to simulate via sudo
		return SimulateUpgrade(ctx)
	}
	return UpdatesStatus{Output: strings.TrimSpace(string(out))}, nil
}
