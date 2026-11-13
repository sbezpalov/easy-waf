# Development host

Easy Home WAF targets **Ubuntu 24.04 LTS**, and several things it does — nftables,
netplan, systemd units, `haproxy -c` against a real HAProxy — cannot be exercised
anywhere else. The practical setup is therefore: edit locally (often on Windows),
run builds and checks on a Linux host that looks like the appliance.

This page describes that host generically. **Keep your own addresses in
`~/.ssh/config`, not in the repository** — a hostname plus an internal IP is
useful reconnaissance and there is no reason for it to be public.

Throughout, `waf-dev` is the SSH alias for your Linux host; substitute your own.

## 1. SSH

Add a block to `~/.ssh/config` (same file on Windows OpenSSH, Linux and macOS):

```ssh-config
Host waf-dev
    HostName 192.0.2.10          # your host's address or DNS name
    User youruser
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
```

Check it:

```bash
ssh waf-dev 'uname -a && test -d ~/easy-waf && echo repo-ok'
```

### After reinstalling the VM

A fresh OS has a **different SSH host key**, so OpenSSH refuses to connect with
`REMOTE HOST IDENTIFICATION HAS CHANGED`. That is expected here and not a
man-in-the-middle — drop the stale entry and accept the new key deliberately:

```bash
ssh-keygen -R 192.0.2.10
ssh -o StrictHostKeyChecking=accept-new waf-dev 'uname -a'
```

Do not make `StrictHostKeyChecking=accept-new` permanent in the config: it is a
one-off for a host you just rebuilt yourself.

## 2. Cursor / VS Code — Remote SSH

1. Install the **Remote - SSH** extension.
2. **Remote-SSH: Connect to Host…** → pick your alias.
3. Open the repository on the host, e.g. `~/easy-waf`.

To stop the IDE asking which platform the host runs on every connect, add the
mapping to your **user** settings (not the repository's — the alias is yours):

```json
{
  "remote.SSH.remotePlatform": { "waf-dev": "linux" }
}
```

## 3. Running the checks there

The reference environment is Ubuntu 24.04, which is also what CI uses
(`ubuntu:24.04` container in every `ci.yml` job). On the dev host:

```bash
ssh waf-dev 'cd ~/easy-waf && git pull && make ci'
```

`make ci` covers `go vet`, the pinned `golangci-lint`, `go test -p 1 ./...` and
`make verify` (including ShellCheck). Two things only a Linux host with HAProxy
installed can prove:

```bash
# golden configurations actually load in HAProxy
ssh waf-dev 'cd ~/easy-waf && go test ./internal/haproxy/... -tags=integration \
  -run TestGoldenConfigsPassHaproxyCheck -count=1'

# a live appliance still works after an upgrade
ssh waf-dev 'cd ~/easy-waf && sudo bash scripts/smoke-appliance.sh'
```

Pull on the host **before** running anything, or you will be testing older code
and chasing failures that do not exist.

## 4. Working from Windows or macOS

Windows and macOS support native Go development. Ubuntu 24.04 remains the
appliance validation target. The same native commands work in PowerShell and
POSIX shells:

```text
go test -p 1 -count=1 ./...
go vet ./...
```

Set `DATABASE_URL` to a disposable test PostgreSQL instance for integration
coverage; without it, database-dependent tests skip. Packages share settings,
revisions and other state in that database, so run them one at a time (`-p 1`),
as `make test` and CI do. Do not run multiple test commands against the same
database concurrently or use an appliance's production database.

- shell scripts must keep **LF** endings (`.gitattributes` enforces
  `scripts/**/*.sh text eol=lf`; bash fails on CRLF with `$'\r': command not found`);
- never commit `.exe` or `.dll` build artifacts — `scripts/check-linux-artifacts.sh`
  fails the build if you do;
- native Go tests cover components; the complete `make ci` gate also needs a
  POSIX shell and its verification tools. On Windows use a prepared Git Bash/
  WSL environment or the dev host; on macOS use the native POSIX environment.
  HAProxy/systemd/appliance checks still run on the Ubuntu target.
