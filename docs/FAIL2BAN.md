# Fail2Ban integration

Fail2Ban protects **SSH** (and optional jails) on the appliance. Easy WAF installs the package via `scripts/install.sh` when available (`apt install fail2ban` on Ubuntu 24.04).

## Management API (UI)

Authenticated session (same JWT + `X-Requested-With` as other mutating routes):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/integrations/fail2ban` | Daemon ping + jail list with banned IPs |
| `GET` | `/api/v1/integrations/fail2ban/jails/{jail}` | One jail status |
| `POST` | `/api/v1/integrations/fail2ban/unban` | Body `{ "jail": "sshd", "ip": "203.0.113.1" }` |

Audit: explicit `fail2ban.unban` plus HTTP audit category **fail2ban**.

## Permissions

`easy-waf-api` runs as user **`easy-waf`** with **`NoNewPrivileges=true`** (see `packaging/systemd/easy-waf-api.service`). That means **`sudo` cannot elevate** to root even with NOPASSWD sudoers — the UI would show *"no new privileges"* errors.

The supported path is **group access to the fail2ban Unix socket** (no sudo):

1. User **`easy-waf`** is in group **`fail2ban`** (`usermod` + `easy-waf-api.service.d/fail2ban.conf` with `SupplementaryGroups=fail2ban`).
2. Drop-in **`fail2ban.service.d/easy-waf-socket.conf`** sets the socket to group **`fail2ban`**, mode **660**, and the runtime directory to **710**.

`scripts/install.sh` runs **`install_fail2ban_api_access`** when the fail2ban package is present. On **Ubuntu**, the `fail2ban` apt package often does **not** create a `fail2ban` group — the installer **creates** it and sets socket mode **660**.

### Repair on an existing host

```bash
cd ~/easy-waf
sudo bash scripts/fix-fail2ban-api-access.sh
```

Or full install: `sudo bash scripts/install.sh`

Verify as the API user:

```bash
sudo -u easy-waf fail2ban-client ping
sudo -u easy-waf fail2ban-client status
```

### Optional sudo (non-appliance only)

Set **`EASY_WAF_FAIL2BAN_USE_SUDO=1`** only if the API process runs **without** `NoNewPrivileges` and `/etc/sudoers.d/easy-waf-fail2ban` is present. Stock **`easy-waf-api`** does not set this; it relies on group socket access instead.

## UI

Open **Fail2Ban** in the management UI:

1. **Refresh jails** — loads overview and fills the unban jail dropdown.
2. Per-jail table — **Unban** next to each banned IP.
3. **Unban IP** form — pick jail + IP, confirm, submit.

If fail2ban is not installed or not running, the status line explains the daemon state; jails may be empty.

## Verification

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
systemctl status fail2ban
ls -la /var/run/fail2ban/fail2ban.sock /run/fail2ban/fail2ban.sock 2>/dev/null
```

From another host (with API token): `GET /api/v1/integrations/fail2ban` on the management listener (LAN CIDR only).
