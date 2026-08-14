package hostd

import (
	"context"
	"fmt"
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

func revertNft(token string) error {
	bak := rollbackBackupPath("nft", token)
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		return nil
	}
	if sz, _ := fileSize(bak); sz > 0 {
		if err := copyFile(bak, nftRulesPath, 0o644); err != nil {
			return err
		}
		ctx := context.Background()
		_, stderr, code, err := runCmd(ctx, DefaultRunner, "/usr/sbin/nft", "-f", nftRulesPath)
		if err != nil || code != 0 {
			return fmt.Errorf("nft -f: %s", string(stderr))
		}
	}
	_ = os.Remove(bak)
	logOp("nft reverted (token %s)", token)
	return nil
}

func revertNetplan(token string) error {
	bak := rollbackBackupPath("netplan", token)
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		return nil
	}
	if sz, _ := fileSize(bak); sz > 0 {
		if err := copyFile(bak, netplanPath, 0o600); err != nil {
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
	_ = os.Remove(bak)
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
	if err := ensureDir(rollbackDir); err != nil {
		return failResp(err.Error(), 1)
	}
	bak := rollbackBackupPath("nft", token)
	if _, err := os.Stat(nftRulesPath); err == nil {
		if err := copyFile(nftRulesPath, bak, 0o644); err != nil {
			return failResp(err.Error(), 1)
		}
	} else if err := touchEmpty(bak); err != nil {
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
	_ = os.Remove(rollbackBackupPath("nft", token))
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
	if err := ensureDir(rollbackDir); err != nil {
		return failResp(err.Error(), 1)
	}
	bak := rollbackBackupPath("netplan", token)
	if _, err := os.Stat(netplanPath); err == nil {
		if err := copyFile(netplanPath, bak, 0o600); err != nil {
			return failResp(err.Error(), 1)
		}
	} else if err := touchEmpty(bak); err != nil {
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
	_ = os.Remove(rollbackBackupPath("netplan", token))
	logOp("netplan change committed (token %s)", token)
	return okResp(nil, nil, 0)
}
