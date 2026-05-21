package hostd

import (
	"context"
	"os"
	"os/user"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/systemdallow"
)

// Dispatcher executes allowlisted privileged operations.
type Dispatcher struct {
	Runner CommandRunner
}

// Dispatch runs argv[0] and returns a Response. Never executes unknown opcodes.
func (d *Dispatcher) Dispatch(ctx context.Context, argv []string) Response {
	if len(argv) == 0 {
		return failResp("empty argv", 1)
	}
	r := d.Runner
	if r == nil {
		r = DefaultRunner
	}
	op := argv[0]
	logOp("op=%s argc=%d", op, len(argv)-1)

	switch op {
	case "systemctl":
		if len(argv) != 3 {
			return failResp("systemctl: want action unit", 1)
		}
		action, unit := argv[1], argv[2]
		if !systemdallow.AllowedUnit(unit) || !systemdallow.AllowedAction(action) {
			return failResp("systemctl: not allowed", 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "systemctl", action, unit)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "nft-list":
		stdout, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "list", "ruleset")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "nft-apply":
		if _, err := os.Stat(nftRulesPath); err != nil {
			return failResp("missing rules file", 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "-c", "-f", nftRulesPath)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		stdout, stderr, code, err = runCmd(ctx, r, "/usr/sbin/nft", "-f", nftRulesPath)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "nft-install":
		if len(argv) != 2 || !hostspec.ValidStagedPath(argv[1]) {
			return failResp("nft-install: invalid staged path", 1)
		}
		src := argv[1]
		stdout, stderr, code, err := runCmd(ctx, r, "/usr/sbin/nft", "-c", "-f", src)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		if err := copyFile(src, nftRulesPath, 0o644); err != nil {
			return failResp(err.Error(), 1)
		}
		stdout, stderr, code, err = runCmd(ctx, r, "/usr/sbin/nft", "-f", nftRulesPath)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "nft-apply-confirm":
		if len(argv) != 4 {
			return failResp("nft-apply-confirm: bad argc", 1)
		}
		return nftApplyConfirm(ctx, r, argv[1], argv[2], argv[3])

	case "nft-commit":
		if len(argv) != 2 {
			return failResp("nft-commit: want token", 1)
		}
		return nftCommit(ctx, r, argv[1])

	case "nft-revert":
		if len(argv) != 2 {
			return failResp("nft-revert: want token", 1)
		}
		if !hostspec.ValidToken(argv[1]) {
			return failResp("invalid token", 1)
		}
		if err := revertNft(argv[1]); err != nil {
			return failResp(err.Error(), 1)
		}
		return okResp(nil, nil, 0)

	case "netplan-apply":
		stdout, stderr, code, err := runCmd(ctx, r, "netplan", "apply")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "netplan-install":
		if len(argv) != 2 || !hostspec.ValidStagedPath(argv[1]) {
			return failResp("netplan-install: invalid staged path", 1)
		}
		if err := copyFile(argv[1], netplanPath, 0o600); err != nil {
			return failResp(err.Error(), 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "netplan", "apply")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "netplan-apply-confirm":
		if len(argv) != 4 {
			return failResp("netplan-apply-confirm: bad argc", 1)
		}
		return netplanApplyConfirm(ctx, r, argv[1], argv[2], argv[3])

	case "netplan-commit":
		if len(argv) != 2 {
			return failResp("netplan-commit: want token", 1)
		}
		return netplanCommit(ctx, r, argv[1])

	case "netplan-revert":
		if len(argv) != 2 {
			return failResp("netplan-revert: want token", 1)
		}
		if !hostspec.ValidToken(argv[1]) {
			return failResp("invalid token", 1)
		}
		if err := revertNetplan(argv[1]); err != nil {
			return failResp(err.Error(), 1)
		}
		return okResp(nil, nil, 0)

	case "apt-update":
		stdout, stderr, code, err := runCmd(ctx, r, "apt-get", "update", "-qq")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "apt-upgrade":
		stdout, stderr, code, err := runCmd(ctx, r, "apt-get", "upgrade", "-y", "-qq")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "apt-simulate":
		stdout, stderr, code, err := runCmd(ctx, r, "apt-get", "-s", "upgrade")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "apt-autoremove-simulate":
		stdout, stderr, code, err := runCmd(ctx, r, "apt-get", "-s", "autoremove")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "journal":
		jargs := argv[1:]
		if err := hostspec.ValidateJournalArgs(jargs); err != nil {
			return failResp(err.Error(), 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "journalctl", jargs...)
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "reboot":
		stdout, stderr, code, err := runCmd(ctx, r, "systemctl", "reboot")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "poweroff":
		stdout, stderr, code, err := runCmd(ctx, r, "systemctl", "poweroff")
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "useradd":
		if len(argv) != 2 || !hostspec.ValidUsername(argv[1]) {
			return failResp("useradd: invalid username", 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "useradd", "-m", "-s", "/bin/bash", argv[1])
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "userdel":
		if len(argv) != 2 || !hostspec.DeletableUsername(argv[1]) {
			return failResp("userdel: not allowed", 1)
		}
		stdout, stderr, code, err := runCmd(ctx, r, "userdel", "-r", argv[1])
		if err != nil || code != 0 {
			return failExec(stdout, stderr, code, err)
		}
		return okResp(stdout, stderr, code)

	case "ssh-authorized-keys":
		if len(argv) != 3 || !hostspec.ValidUsername(argv[1]) || !hostspec.ValidStagedPath(argv[2]) {
			return failResp("ssh-authorized-keys: invalid args", 1)
		}
		return sshAuthorizedKeys(ctx, r, argv[1], argv[2])

	case "fail2ban":
		return dispatchFail2ban(ctx, r, argv[1:])

	default:
		return failResp("unknown op: "+op, 1)
	}
}

func sshAuthorizedKeys(ctx context.Context, r CommandRunner, username, tmp string) Response {
	u, err := user.Lookup(username)
	if err != nil {
		return failResp("user not found", 1)
	}
	dir := u.HomeDir + "/.ssh"
	stdout, stderr, code, err := runCmd(ctx, r, "install", "-d", "-m", "0700", "-o", username, "-g", username, dir)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	dest := dir + "/authorized_keys"
	stdout, stderr, code, err = runCmd(ctx, r, "install", "-m", "0600", "-o", username, "-g", username, tmp, dest)
	if err != nil || code != 0 {
		return failExec(stdout, stderr, code, err)
	}
	return okResp(stdout, stderr, code)
}
