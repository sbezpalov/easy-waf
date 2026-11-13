// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
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
	// nftGuardPath is the root-owned management port restriction; see reloadNftGuard.
	nftGuardPath = "/etc/nftables/easy-waf-guard.nft"
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

func stopRollbackUnit(ctx context.Context, r CommandRunner, kind, token string) error {
	unit := fmt.Sprintf("easy-waf-rb-%s-%s", kind, token)
	// systemd-run --on-active creates a timer as well as a service. Stopping
	// only the service leaves the timer armed and able to start it again.
	_, stderr, code, err := runCmd(ctx, r, binSystemctl, "stop", unit+".timer", unit+".service")
	if err != nil {
		return fmt.Errorf("stop rollback units: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("stop rollback units (exit %d): %s", code, strings.TrimSpace(string(stderr)))
	}
	_, _, _, _ = runCmd(ctx, r, binSystemctl, "reset-failed", unit+".service")
	return nil
}

// RunRevert restores backup for kind (nft|netplan); used by CLI and transient timer.
func RunRevert(kind, token string) error {
	if !hostspec.ValidToken(token) {
		return fmt.Errorf("invalid token")
	}
	unlock, err := lockRollback(true)
	if err != nil {
		return err
	}
	defer unlock()
	return runRevert(kind, token)
}

// runRevert is used when the caller already holds the operation lock.
func runRevert(kind, token string) error {
	switch kind {
	case "nft":
		return revertNft(token)
	case "netplan":
		return revertNetplan(token)
	default:
		return fmt.Errorf("unknown kind")
	}
}

// saveRollbackBackup copies the current root-owned file into the root-only
// hostd state directory. An absent source is recorded as an empty backup, which
// tells the revert to remove only the newly declared managed tables for nft.
//
// The write also goes through descriptor-anchored state-directory helpers.
func saveRollbackBackup(kind, src, bak string, mode os.FileMode) error {
	var data []byte
	f, err := os.Open(src)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		defer f.Close()
		data, err = readRollbackContents(f)
		if err != nil {
			return err
		}
	}
	// Reject a baseline that the safety revert would refuse, before arming
	// anything or replacing the live file.
	if len(data) > 0 {
		switch kind {
		case "nft":
			err = hostspec.ValidateNftRuleset(data)
		case "netplan":
			err = validateNetplanYAML(data)
		default:
			err = fmt.Errorf("unknown rollback kind")
		}
		if err != nil {
			return fmt.Errorf("rollback baseline rejected: %w", err)
		}
	}
	return stateWriteFile(bak, data, mode)
}

func readRollbackContents(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("rollback source is not a regular file")
	}
	if info.Size() > maxRollbackBackupBytes {
		return nil, fmt.Errorf("rollback backup exceeds %d bytes", maxRollbackBackupBytes)
	}
	// Check the read length too: the file may grow after Stat. Never pass a
	// silently truncated configuration to nft or netplan.
	data, err := io.ReadAll(io.LimitReader(f, maxRollbackBackupBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRollbackBackupBytes {
		return nil, fmt.Errorf("rollback backup exceeds %d bytes", maxRollbackBackupBytes)
	}
	return data, nil
}

// readRollbackBackup returns the saved contents, or ok=false when there is no
// backup to restore.
//
// The read goes through stateOpenFile rather than os.ReadFile so rollback state
// remains descriptor-anchored even if deployment ownership drifts. See
// statefile.go.
func readRollbackBackup(bak string) (data []byte, ok bool, err error) {
	f, err := stateOpenFile(bak)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	b, err := readRollbackContents(f)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// reloadNftGuard puts the management port restriction back after a ruleset was
// loaded. easy-waf-api chooses that ruleset, and a compromised one could accept
// everything or flush the lot, so the restriction lives in a file only root can
// write and is loaded last: a drop in any base chain is final, and the file
// replaces its table whole. There is no file when the operator runs the
// firewall (EASY_WAF_NFT_MGMT_LAN=0).
func reloadNftGuard(ctx context.Context, r CommandRunner) error {
	if _, err := os.Stat(nftGuardPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "-f", nftGuardPath)
	if err != nil {
		return fmt.Errorf("reload firewall guard: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("reload firewall guard: %s", strings.TrimSpace(string(stderr)))
	}
	return nil
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
	if len(data) == 0 || string(data) == nftEmptyRuleset {
		// No managed ruleset existed before this change, so undo it by removing
		// the tables it declared. The persisted empty-ruleset marker has the
		// same meaning on later apply/revert cycles. Never globally flush:
		// fail2ban, CrowdSec and Docker may own other tables.
		current, err := os.ReadFile(nftRulesPath)
		if err != nil {
			return fmt.Errorf("read current managed ruleset: %w", err)
		}
		// Cleanup or guard reload may have failed after the previous attempt
		// removed the tables and wrote the marker. Retry the remaining steps.
		if string(current) != nftEmptyRuleset {
			script := nftDestroyScript(current)
			if script == "" {
				return fmt.Errorf("nft revert: managed ruleset declares no table to destroy (refusing global flush)")
			}
			if err := runNftScript(ctx, script); err != nil {
				return err
			}
		}
		if err := writeFileAtomic(nftRulesPath, []byte(nftEmptyRuleset), nftRulesMode); err != nil {
			return err
		}
		if err := reloadNftGuard(ctx, DefaultRunner); err != nil {
			return err
		}
		if err := removePendingRollback(bak); err != nil {
			return err
		}
		logOp("nft reverted to no managed ruleset (token %s)", token)
		return nil
	}
	// Validate root-owned backup contents too, as defense in depth against
	// damaged state or unsafe privileged maintenance.
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
	if err := reloadNftGuard(ctx, DefaultRunner); err != nil {
		return err
	}
	if err := removePendingRollback(bak); err != nil {
		return err
	}
	logOp("nft reverted (token %s)", token)
	return nil
}

// nftEmptyRuleset is what the managed file holds when there is no managed
// ruleset; /etc/nftables.conf still includes it at boot.
const nftEmptyRuleset = "#!/usr/sbin/nft -f\n# Managed by Easy Home WAF — no managed ruleset.\n"

var nftTableRE = regexp.MustCompile(`(?m)^\s*(?:add\s+|create\s+)?table\s+(?:(ip|ip6|inet|arp|bridge|netdev)\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*\{?`)

// nftDestroyScript returns statements removing every table ruleset declares.
// Empty string means the ruleset named no tables — callers must hard-fail
// instead of falling back to a global flush.
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
		// Never global-flush: that would wipe fail2ban/CrowdSec/Docker and the
		// management guard. Callers must treat empty as a hard error.
		return ""
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
		if err := validateNetplanYAML(data); err != nil {
			return fmt.Errorf("backup rejected: %w", err)
		}
	}
	if len(data) > 0 {
		if err := writeFileAtomic(netplanPath, data, netplanMode); err != nil {
			return err
		}
	} else {
		if err := os.Remove(netplanPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove netplan configuration: %w", err)
		}
	}
	ctx := context.Background()
	_, stderr, code, err := runCmd(ctx, DefaultRunner, binNetplan, "apply")
	if err != nil || code != 0 {
		return fmt.Errorf("netplan apply: %s", string(stderr))
	}
	if err := removePendingRollback(bak); err != nil {
		return err
	}
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
	if err := rejectPendingChange(kind); err != nil {
		return err
	}
	if err := saveRollbackBackup(kind, livePath, bak, mode); err != nil {
		return err
	}
	if err := scheduleRevert(ctx, r, kind, token, timeoutSec); err != nil {
		return errors.Join(err, removePendingRollback(bak))
	}
	return nil
}

// Caller holds the operation lock while inspecting and changing pending state.
func rejectPendingChange(kind string) error {
	// Each subsystem owns one live file. A second token would back up the
	// first unconfirmed configuration and give two timers conflicting history.
	dir, err := stateOpenFile(filepath.Join(stateDir, "rollback"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect pending changes: %w", err)
	}
	if err == nil {
		entries, readErr := dir.ReadDir(-1)
		_ = dir.Close()
		if readErr != nil {
			return fmt.Errorf("inspect pending changes: %w", readErr)
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, kind+"-") && strings.HasSuffix(name, ".bak") {
				return fmt.Errorf("%s already has a pending change; confirm it or wait for rollback", kind)
			}
		}
	}
	return nil
}

// abortConfirmedChange puts the previous state back right away after the
// change itself failed part-way (for example a netplan file that `netplan
// generate` rejected, which used to stay in /etc/netplan and take effect at
// the next boot), and cancels the timer.
func abortConfirmedChange(ctx context.Context, r CommandRunner, kind, token string) error {
	stopErr := stopRollbackUnit(ctx, r, kind, token)
	// A systemd failure must not prevent the immediate safety rollback.
	return errors.Join(stopErr, runRevert(kind, token))
}

func commitConfirmedChange(ctx context.Context, r CommandRunner, kind, token string) error {
	backup := rollbackBackupPath(kind, token)
	if _, exists, err := stateFileSize(backup); err != nil {
		return fmt.Errorf("inspect pending rollback: %w", err)
	} else if !exists {
		// Already committed or reverted; transient units may have been collected.
		return nil
	}
	if err := stopRollbackUnit(ctx, r, kind, token); err != nil {
		return err
	}
	return removePendingRollback(backup)
}

func removePendingRollback(backup string) error {
	if err := stateRemoveFile(backup); err != nil {
		return fmt.Errorf("remove pending rollback: %w", err)
	}
	return nil
}

func nftApplyConfirm(ctx context.Context, r CommandRunner, staged, timeoutStr, token string) Response {
	if !hostspec.ValidToken(token) || !hostspec.ValidRollbackTimeout(timeoutStr) {
		return failResp("invalid token or timeout", 1)
	}
	unlock, err := lockRollback(false)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	defer unlock()
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
	stdout, stderr, code, err := runCmd(ctx, r, binNft, "-c", "-f", staged)
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
	stdout, stderr, code, err = runCmd(ctx, r, binNft, "-f", nftRulesPath)
	if err != nil || code != 0 {
		return fail(failExec(stdout, stderr, code, err))
	}
	if err := reloadNftGuard(ctx, r); err != nil {
		return fail(failResp(err.Error(), 1))
	}
	logOp("nft applied with rollback in %ds (token %s)", timeoutSec, token)
	return okResp(stdout, stderr, 0)
}

func nftCommit(ctx context.Context, r CommandRunner, token string) Response {
	if !hostspec.ValidToken(token) {
		return failResp("invalid token", 1)
	}
	unlock, err := lockRollback(false)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	defer unlock()
	if err := commitConfirmedChange(ctx, r, "nft", token); err != nil {
		return failResp(err.Error(), 1)
	}
	logOp("nft change committed (token %s)", token)
	return okResp(nil, nil, 0)
}

func netplanApplyConfirm(ctx context.Context, r CommandRunner, staged, timeoutStr, token string) Response {
	if !hostspec.ValidToken(token) || !hostspec.ValidRollbackTimeout(timeoutStr) {
		return failResp("invalid token or timeout", 1)
	}
	unlock, err := lockRollback(false)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	defer unlock()
	stagedCopy, cleanup, err := materializeStagedFile(staged)
	if err != nil {
		return failResp("invalid staged path: "+err.Error(), 1)
	}
	defer cleanup()
	staged = stagedCopy
	if err := validateNetplanFile(staged); err != nil {
		return failResp("netplan-apply-confirm: "+err.Error(), 1)
	}
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
	stdout, stderr, code, err := runCmd(ctx, r, binNetplan, "generate")
	if err != nil || code != 0 {
		return fail(failExec(stdout, stderr, code, err))
	}
	stdout, stderr, code, err = runCmd(ctx, r, binNetplan, "apply")
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
	unlock, err := lockRollback(false)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	defer unlock()
	if err := commitConfirmedChange(ctx, r, "netplan", token); err != nil {
		return failResp(err.Error(), 1)
	}
	logOp("netplan change committed (token %s)", token)
	return okResp(nil, nil, 0)
}
