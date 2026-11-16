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

A fresh OS may have a **different SSH host key**, so OpenSSH can refuse to
connect with `REMOTE HOST IDENTIFICATION HAS CHANGED`. The warning alone does
not prove that the endpoint is the VM you rebuilt. Confirm the VM's identity
through its trusted hypervisor console before replacing the saved key.

On the VM console, record the public Ed25519 host key's SHA-256 fingerprint:

```bash
ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub
```

On your workstation, remove only that host's stale entry (use the actual
address or host-key alias named in the warning), then request confirmation for
the matching key type:

```bash
ssh-keygen -R 192.0.2.10
ssh -o StrictHostKeyChecking=ask -o HostKeyAlgorithms=ssh-ed25519 waf-dev 'uname -a'
```

Compare the fingerprint in the SSH prompt with the one from the VM console
before answering `yes`. If they differ, or the rebuild was unexpected, stop and
investigate. Do not disable host-key checking or automatically accept a changed
identity. See OpenSSH's [host-key verification guidance](https://manpages.ubuntu.com/manpages/noble/man1/ssh.1.html#VERIFYING_HOST_KEYS).

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

When authenticated GeoIP lookup returns a non-200 response, smoke fails rather
than skipping it. Check the configured database/provider and upstream limits;
for example, IPinfo rate limiting can surface as management API HTTP 502.
An unavailable optional MMDB upload input is still a separate skipped check.

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
