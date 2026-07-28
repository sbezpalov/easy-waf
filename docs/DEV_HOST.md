# Pilot host `waf-dev` (EasyWAF development and test)

Short alias **`waf-dev`** is the target Linux host for the EasyWAF pilot (**Ubuntu 24.04 LTS**). Code is edited locally (often on Windows); builds and checks run on this host or in CI.

## 1. SSH: `~/.ssh/config`

On **Windows** (OpenSSH) and **Linux**, add a block (set your **`HostName`**: pilot **`192.0.2.10`**, DNS **`waf-dev.home.bezpalov.com`**) and user:

```ssh-config
Host waf-dev
    HostName 192.0.2.10
    User youruser
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
```

Check:

```bash
ssh waf-dev 'uname -a && test -d ~/easy-waf && echo repo-ok'
```

### After reinstalling the VM (Alma → Ubuntu, etc.)

The new OS has a **different SSH host key**. OpenSSH will refuse the connection with `REMOTE HOST IDENTIFICATION HAS CHANGED`. That is expected (not MITM) — remove the old entry and accept the new key:

```bash
# Windows (PowerShell) or Linux/macOS
ssh-keygen -R 192.0.2.10
# on first connect: ssh with -o StrictHostKeyChecking=accept-new
ssh -o StrictHostKeyChecking=accept-new waf-dev 'uname -a'
```

If the **IP** or **DNS** changed — update `HostName` in `~/.ssh/config` and, if needed, the IP line in this file.

**DNS (LAN):** `waf-dev.home.bezpalov.com` → `192.0.2.10` (if `~/.ssh/config` uses the IP, DNS is optional).

## 2. Cursor / VS Code — Remote SSH

1. Extension **Remote - SSH**.
2. **Remote-SSH: Connect to Host…** → select **`waf-dev`**.
3. Open the repo folder on the host, e.g. `~/easy-waf`.

Repo root **`.vscode/settings.json`** sets `remote.SSH.remotePlatform` for **`waf-dev`** → Linux so the IDE does not ask for the platform on every connect.

## 3. Git on the pilot

After SSH, use the Linux clone as usual (`git pull`, `make ci`, **`make verify`** — including **ShellCheck** on `scripts/install.sh`). Local `go.mod` / untracked `go.sum` conflicts with `git pull` — see assistant hints or `docs/DEPLOYMENT.md`.

## 4. Alignment with CI

The reference environment is **Ubuntu 24.04** (`make ci` on the pilot and **GitHub Actions**: `ubuntu:24.04` container in all jobs). On Windows, before push, run the same steps from **Git Bash / WSL** (see `.cursor/rules/easy-waf-verify-after-edits.mdc`).
