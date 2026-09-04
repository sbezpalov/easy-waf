// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

const (
	rollbackDir  = "/var/lib/easy-waf/rollback"
	nftRulesPath = "/etc/nftables/easy-waf.nft"
	netplanPath  = "/etc/netplan/99-easy-waf.yaml"
	hostdBin     = "/usr/sbin/easy-waf-hostd"

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
	return filepath.Join(rollbackDir, kind+"-"+token+".bak")
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
	// An empty backup means no managed ruleset existed before this change, so a
	// revert has to flush back to empty. Skipping the reload in that case — as
	// this used to — left the newly applied firewall rules live after a rollback
	// meant to undo them, including the rollback that fires when the operator
	// locks themselves out. revertNetplan already handles the empty case.
	if len(data) == 0 {
		data = []byte("flush ruleset\n")
	}
	if err := writeFileAtomic(nftRulesPath, data, nftRulesMode); err != nil {
		return err
	}
	ctx := context.Background()
	_, stderr, code, err := runCmd(ctx, DefaultRunner, "/usr/sbin/nft", "-f", nftRulesPath)
	if err != nil || code != 0 {
		return fmt.Errorf("nft -f: %s", string(stderr))
	}
	_ = stateRemoveFile(bak)
	logOp("nft reverted (token %s)", token)
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
	timeoutSec, _ := strconv.Atoi(timeoutStr)
	bak := rollbackBackupPath("nft", token)
	if err := saveRollbackBackup(nftRulesPath, bak, 0o644); err != nil {
		return failResp(err.Error(), 1)
	}
	stdout, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "-c", "-f", staged)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	if err := copyFile(staged, nftRulesPath, 0o644); err != nil {
		return failResp(err.Error(), 1)
	}
	stdout, stderr, code, err = runCmd(ctx, r, "/usr/sbin/nft", "-f", nftRulesPath)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	if err := scheduleRevert(ctx, r, "nft", token, timeoutSec); err != nil {
		return failResp(err.Error(), 1)
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
	bak := rollbackBackupPath("netplan", token)
	if err := saveRollbackBackup(netplanPath, bak, 0o600); err != nil {
		return failResp(err.Error(), 1)
	}
	if err := copyFile(staged, netplanPath, 0o600); err != nil {
		return failResp(err.Error(), 1)
	}
	stdout, stderr, code, err := runCmd(ctx, r, "netplan", "generate")
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	stdout, stderr, code, err = runCmd(ctx, r, "netplan", "apply")
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	if err := scheduleRevert(ctx, r, "netplan", token, timeoutSec); err != nil {
		return failResp(err.Error(), 1)
	}
	logOp("netplan applied with rollback in %ds (token %s)", timeoutSec, token)
	return okResp(stdout, stderr, 0)
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
