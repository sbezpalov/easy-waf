package apt

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// UpdatesStatus is apt preview or command result.
type UpdatesStatus struct {
	Output   string   `json:"output,omitempty"`
	Packages []string `json:"packages,omitempty"`
}

var autoremoveRemvRE = regexp.MustCompile(`(?m)^Remv\s+(\S+)`)

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

// aptPrivilegedFn is runner.Privileged; overridden in tests.
var aptPrivilegedFn = runner.Privileged

// AutoremovePreview returns packages apt-get autoremove would remove (simulate only).
func AutoremovePreview(ctx context.Context) (UpdatesStatus, error) {
	out, err := aptPrivilegedFn(ctx, "apt-autoremove-simulate")
	output := string(out)
	return UpdatesStatus{
		Output:   output,
		Packages: ParseAutoremovePackages(output),
	}, err
}

// ParseAutoremovePackages extracts package names from apt-get -s autoremove output.
func ParseAutoremovePackages(output string) []string {
	matches := autoremoveRemvRE.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var pkgs []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		pkg := m[1]
		if _, ok := seen[pkg]; ok {
			continue
		}
		seen[pkg] = struct{}{}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// AutoremoveNothingToDo reports whether simulate output indicates nothing to remove.
func AutoremoveNothingToDo(st UpdatesStatus) bool {
	if len(st.Packages) > 0 {
		return false
	}
	low := strings.ToLower(st.Output)
	return strings.Contains(low, "0 to remove") && !strings.Contains(low, "remv ")
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
