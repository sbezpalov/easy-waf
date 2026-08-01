package apt

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
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

// SetPrivilegedFnForTest overrides broker calls in tests; returns the previous function.
func SetPrivilegedFnForTest(fn func(context.Context, ...string) ([]byte, error)) func(context.Context, ...string) ([]byte, error) {
	prev := aptPrivilegedFn
	aptPrivilegedFn = fn
	return prev
}

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
	pkgs := make([]string, 0, len(matches))
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

// CacheSizeBytes returns the size of /var/cache/apt/archives (du -sb via broker).
func CacheSizeBytes(ctx context.Context) (int64, error) {
	out, err := aptPrivilegedFn(ctx, "apt-cache-size")
	if err != nil {
		return 0, err
	}
	return ParseCacheSizeBytes(string(out))
}

// ParseCacheSizeBytes parses du -sb output: "<bytes>\t/path".
func ParseCacheSizeBytes(output string) (int64, error) {
	line := strings.TrimSpace(output)
	if line == "" {
		return 0, nil
	}
	field := strings.Fields(line)[0]
	n, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("apt cache size: parse %q: %w", field, err)
	}
	if n < 0 {
		return 0, nil
	}
	return n, nil
}

// CleanCache runs apt-get clean via the host broker.
func CleanCache(ctx context.Context) error {
	_, err := aptPrivilegedFn(ctx, "apt-clean")
	return err
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
