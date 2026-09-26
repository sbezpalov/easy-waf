// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// Live files the broker manages (variables so tests can point them elsewhere).
var (
	nftRulesPath = "/etc/nftables/easy-waf.nft"
	netplanPath  = "/etc/netplan/99-easy-waf.yaml"
	// runtimeDir holds root-only scratch files (materialized staging copies).
	runtimeDir = "/run/easy-waf"
)

const (
	hostdBin = "/usr/sbin/easy-waf-hostd"

	// maxRollbackBackupBytes bounds what a revert will read back. A netplan file
	// or an nftables ruleset is kilobytes; the limit is only here so a backup that
	// grew unexpectedly cannot be loaded whole into the broker.
	maxRollbackBackupBytes = 16 << 20

	// nftRulesMode matches what the apply path writes, so a revert cannot leave
	// the ruleset file with different permissions than a normal apply.
	nftRulesMode os.FileMode = 0o644
	// netplanMode: netplan warns about world-readable configuration.
	netplanMode os.FileMode = 0o600
)

func rollbackBackupPath(kind, token string) string {
	return filepath.Join(stateDir, "rollback", kind+"-"+token+".bak")
}

func scheduleRevert(ctx context.Context, r CommandRunner, kind, token string, timeoutSec int) error {
	unit := fmt.Sprintf("easy-waf-rb-%s-%s", kind, token)
	_, stderr, code, err := runCmd(ctx, r, "systemd-run", "--collect",
		"--unit="+unit,
		fmt.Sprintf("--on-active=%ds", timeoutSec),
		hostdBin, "revert", kind, token)
	if err != nil || code != 0 {
		return fmt.Errorf("systemd-run: %s", string(stderr))
	}
	return nil
}

func stopRollbackUnit(ctx context.Context, r CommandRunner, kind, token string) {
	unit := fmt.Sprintf("easy-waf-rb-%s-%s", kind, token)
	_, _, _, _ = runCmd(ctx, r, "systemctl", "stop", unit+".service")
	_, _, _, _ = runCmd(ctx, r, "systemctl", "reset-failed", unit+".service")
}

// RunRevert restores backup for kind (nft|netplan); used by CLI and transient timer.
func RunRevert(kind, token string) error {
	if !hostspec.ValidToken(token) {
		return fmt.Errorf("invalid token")
	}
	switch kind {
	case "nft":
		return revertNft(token)
	case "netplan":
		return revertNetplan(token)
	default:
		return fmt.Errorf("unknown kind")
	}
}

// saveRollbackBackup copies the current root-owned file into the rollback
// directory. An absent source is recorded as an empty backup, which is what
// tells the revert to flush back to nothing.
//
// The write also goes through the state-directory helpers: os.CreateTemp in the
// destination directory — what this used to do — resolves that directory
// normally, so replacing it with a symlink made root create files wherever the
// easy-waf account chose.
func saveRollbackBackup(src, bak string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		data = nil
	}
	return stateWriteFile(bak, data, mode)
}

// readRollbackBackup returns the saved contents, or ok=false when there is no
// backup to restore.
//
// The read goes through stateOpenFile rather than os.ReadFile because the
// rollback directory belongs to the unprivileged easy-waf account. A plain read
// here was a root file-disclosure primitive: a compromised easy-waf-api could
// replace the backup with a symlink to /etc/shadow and have root copy it into
// /etc/nftables/easy-waf.nft, which is mode 0644 and readable by that same
// account. See statefile.go.
func readRollbackBackup(bak string) (data []byte, ok bool, err error) {
	sz, exists, err := stateFileSize(bak)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	if sz == 0 {
		return nil, true, nil
	}
	f, err := stateOpenFile(bak)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRollbackBackupBytes))
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func revertNft(token string) error {
	bak := rollbackBackupPath("nft", token)
	data, ok, err := readRollbackBackup(bak)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	ctx := context.Background()
	if len(data) == 0 {
		// No managed ruleset existed before this change, so undo it by removing
		// the tables it declared. A blanket `flush ruleset` would also wipe
		// fail2ban's, CrowdSec's and Docker's tables; it is only the fallback
		// when the applied ruleset declares no table we can name, because
		// removing the rule that locked the operator out matters more.
		current, _ := os.ReadFile(nftRulesPath)
		script := nftDestroyScript(current)
		if err := runNftScript(ctx, script); err != nil {
			return err
		}
		if err := writeFileAtomic(nftRulesPath, []byte(nftEmptyRuleset), nftRulesMode); err != nil {
			return err
		}
		_ = stateRemoveFile(bak)
		logOp("nft reverted to no managed ruleset (token %s)", token)
		return nil
	}
	// The backup sits in a directory the easy-waf account owns; check it like
	// any other ruleset before root loads it.
	if err := hostspec.ValidateNftRuleset(data); err != nil {
		return fmt.Errorf("backup rejected: %w", err)
	}
	if err := writeFileAtomic(nftRulesPath, data, nftRulesMode); err != nil {
		return err
	}
	_, stderr, code, err := runCmd(ctx, DefaultRunner, "/usr/sbin/nft", "-f", nftRulesPath)
	if err != nil || code != 0 {
		return fmt.Errorf("nft -f: %s", string(stderr))
	}
	_ = stateRemoveFile(bak)
	logOp("nft reverted (token %s)", token)
	return nil
}

// nftEmptyRuleset is what the managed file holds when there is no managed
// ruleset; /etc/nftables.conf still includes it at boot.
const nftEmptyRuleset = "#!/usr/sbin/nft -f\n# Managed by Easy Home WAF — no managed ruleset.\n"

var nftTableRE = regexp.MustCompile(`(?m)^\s*(?:add\s+|create\s+)?table\s+(?:(ip|ip6|inet|arp|bridge|netdev)\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*\{?`)

// nftDestroyScript returns statements removing every table ruleset declares,
// or `flush ruleset` when it declares none.
func nftDestroyScript(ruleset []byte) string {
	var b strings.Builder
	seen := map[string]struct{}{}
	for _, m := range nftTableRE.FindAllSubmatch(ruleset, -1) {
		family := string(m[1])
		if family == "" {
			family = "ip"
		}
		key := family + " " + string(m[2])
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		// destroy, unlike delete, does not fail when the table is already gone.
		b.WriteString("destroy table " + key + "\n")
	}
	if b.Len() == 0 {
		return "flush ruleset\n"
	}
	return b.String()
}

func runNftScript(ctx context.Context, script string) error {
	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(runtimeDir, "revert-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, stderr, code, err := runCmd(ctx, DefaultRunner, "/usr/sbin/nft", "-f", f.Name())
	if err != nil || code != 0 {
		return fmt.Errorf("nft -f: %s", string(stderr))
	}
	return nil
}

func revertNetplan(token string) error {
	bak := rollbackBackupPath("netplan", token)
	data, ok, err := readRollbackBackup(bak)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if len(data) > 0 {
		if err := writeFileAtomic(netplanPath, data, netplanMode); err != nil {
			return err
		}
	} else {
		_ = os.Remove(netplanPath)
	}
	ctx := context.Background()
	_, stderr, code, err := runCmd(ctx, DefaultRunner, "netplan", "apply")
	if err != nil || code != 0 {
		return fmt.Errorf("netplan apply: %s", string(stderr))
	}
	_ = stateRemoveFile(bak)
	logOp("netplan reverted (token %s)", token)
	return nil
}

// beginConfirmedChange records the backup and arms the revert timer before the
// change is made. Arming it afterwards, as this used to, meant a systemd-run
// failure (or a reused token whose unit name was taken) left the new network
// or firewall config live with nothing scheduled to undo it.
func beginConfirmedChange(ctx context.Context, r CommandRunner, kind, token, livePath string, mode os.FileMode, timeoutSec int) error {
	bak := rollbackBackupPath(kind, token)
	// A reused token would overwrite the backup of a change still pending,
	// losing the state that change's revert must restore.
	if _, exists, err := stateFileSize(bak); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("token already has a pending change")
	}
	if err := saveRollbackBackup(livePath, bak, mode); err != nil {
		return err
	}
	if err := scheduleRevert(ctx, r, kind, token, timeoutSec); err != nil {
		_ = stateRemoveFile(bak)
		return err
	}
	return nil
}

// abortConfirmedChange puts the previous state back right away after the
// change itself failed part-way (for example a netplan file that `netplan
// generate` rejected, which used to stay in /etc/netplan and take effect at
// the next boot), and cancels the timer.
func abortConfirmedChange(ctx context.Context, r CommandRunner, kind, token string) error {
	stopRollbackUnit(ctx, r, kind, token)
	return RunRevert(kind, token)
}

func nftApplyConfirm(ctx context.Context, r CommandRunner, staged, timeoutStr, token string) Response {
	if !hostspec.ValidToken(token) || !hostspec.ValidRollbackTimeout(timeoutStr) {
		return failResp("invalid token or timeout", 1)
	}
	stagedCopy, cleanup, err := materializeStagedFile(staged)
	if err != nil {
		return failResp("invalid staged path: "+err.Error(), 1)
	}
	defer cleanup()
	staged = stagedCopy
	if err := validateNftFile(staged); err != nil {
		return failResp("nft-apply-confirm: "+err.Error(), 1)
	}
	timeoutSec, _ := strconv.Atoi(timeoutStr)
	// Validation changes nothing, so it runs before anything is armed.
	stdout, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "-c", "-f", staged)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	if err := beginConfirmedChange(ctx, r, "nft", token, nftRulesPath, nftRulesMode, timeoutSec); err != nil {
		return failResp(err.Error(), 1)
	}
	fail := func(resp Response) Response {
		if aerr := abortConfirmedChange(ctx, r, "nft", token); aerr != nil {
			resp.Error += "; restoring the previous ruleset also failed: " + aerr.Error()
		}
		return resp
	}
	if err := copyFile(staged, nftRulesPath, nftRulesMode); err != nil {
		return fail(failResp(err.Error(), 1))
	}
	stdout, stderr, code, err = runCmd(ctx, r, "/usr/sbin/nft", "-f", nftRulesPath)
	if err != nil || code != 0 {
		return fail(failExec(stdout, stderr, code, err))
	}
	logOp("nft applied with rollback in %ds (token %s)", timeoutSec, token)
	return okResp(stdout, stderr, 0)
}

func nftCommit(ctx context.Context, r CommandRunner, token string) Response {
	if !hostspec.ValidToken(token) {
		return failResp("invalid token", 1)
	}
	stopRollbackUnit(ctx, r, "nft", token)
	_ = stateRemoveFile(rollbackBackupPath("nft", token))
	logOp("nft change committed (token %s)", token)
	return okResp(nil, nil, 0)
}

func netplanApplyConfirm(ctx context.Context, r CommandRunner, staged, timeoutStr, token string) Response {
	if !hostspec.ValidToken(token) || !hostspec.ValidRollbackTimeout(timeoutStr) {
		return failResp("invalid token or timeout", 1)
	}
	stagedCopy, cleanup, err := materializeStagedFile(staged)
	if err != nil {
		return failResp("invalid staged path: "+err.Error(), 1)
	}
	defer cleanup()
	staged = stagedCopy
	timeoutSec, _ := strconv.Atoi(timeoutStr)
	if err := beginConfirmedChange(ctx, r, "netplan", token, netplanPath, netplanMode, timeoutSec); err != nil {
		return failResp(err.Error(), 1)
	}
	fail := func(resp Response) Response {
		if aerr := abortConfirmedChange(ctx, r, "netplan", token); aerr != nil {
			resp.Error += "; restoring the previous netplan also failed: " + aerr.Error()
		}
		return resp
	}
	if err := copyFile(staged, netplanPath, netplanMode); err != nil {
		return fail(failResp(err.Error(), 1))
	}
	stdout, stderr, code, err := runCmd(ctx, r, "netplan", "generate")
	if err != nil || code != 0 {
		return fail(failExec(stdout, stderr, code, err))
	}
	stdout, stderr, code, err = runCmd(ctx, r, "netplan", "apply")
	if err != nil || code != 0 {
		return fail(failExec(stdout, stderr, code, err))
	}
	logOp("netplan applied with rollback in %ds (token %s)", timeoutSec, token)
	return okResp(stdout, stderr, 0)
}

// RevertPendingChanges undoes every confirm-or-revert change still waiting
// for a commit. The revert timer is a transient systemd unit, so a reboot
// inside the window used to cancel it while the new netplan or nftables file
// stayed in /etc: a lockout that survived the reboot meant to escape it.
// easy-waf-hostd calls this at startup; a backup exists only until its change
// is committed or reverted. A restart of the broker itself during a window
// therefore reverts early, which is the safe direction.
func RevertPendingChanges() {
	entries, err := os.ReadDir(filepath.Join(stateDir, "rollback"))
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".bak") {
			continue
		}
		kind, token, ok := strings.Cut(strings.TrimSuffix(name, ".bak"), "-")
		if !ok || (kind != "nft" && kind != "netplan") || !hostspec.ValidToken(token) {
			continue
		}
		if err := RunRevert(kind, token); err != nil {
			logOp("pending %s change %s: revert at startup failed: %v", kind, token, err)
			continue
		}
		logOp("pending %s change %s reverted at startup (never committed)", kind, token)
	}
}

func netplanCommit(ctx context.Context, r CommandRunner, token string) Response {
	if !hostspec.ValidToken(token) {
		return failResp("invalid token", 1)
	}
	stopRollbackUnit(ctx, r, "netplan", token)
	_ = stateRemoveFile(rollbackBackupPath("netplan", token))
	logOp("netplan change committed (token %s)", token)
	return okResp(nil, nil, 0)
}
