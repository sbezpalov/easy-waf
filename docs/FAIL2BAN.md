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

`easy-waf-api` runs as user **`easy-waf`** with **`NoNewPrivileges=true`** (see `packaging/systemd/easy-waf-api.service`). It does **not** call `fail2ban-client` directly or use `sudo`.

Status and unban go through the root broker **`easy-waf-hostd`** on **`/run/easy-waf/hostd.sock`**. The broker runs **`/usr/bin/fail2ban-client`** as root and accepts only these forms:

- `ping`
- `status`
- `status <jail>`
- `set <jail> unbanip <ip>`

Jail names and IPs are validated in **`internal/host/hostspec`** before execution.

Membership in group **`fail2ban`**, socket drop-ins, and **`/etc/sudoers.d/easy-waf-fail2ban`** are **not** required on current installs. `scripts/install.sh` removes those artifacts on upgrade (`cleanup_legacy_fail2ban_access`).

### Requirements

1. **`easy-waf-hostd.service`** is enabled and active.
2. **`fail2ban`** package is installed and **`fail2ban.service`** is running.

Verify the broker and daemon:

```bash
systemctl status easy-waf-hostd fail2ban
ls -la /run/easy-waf/hostd.sock
sudo fail2ban-client ping
sudo fail2ban-client status
```

After code changes: rebuild **`easy-waf-hostd`** and **`easy-waf-api`**, then `systemctl restart easy-waf-hostd easy-waf-api`.

### Legacy socket access (old releases only)

Hosts upgraded from releases before the hostd path may still have group/socket drop-ins. `scripts/fix-fail2ban-api-access.sh` applies the old model for manual repair only. Prefer a normal **`install.sh`** run (which cleans legacy files and relies on hostd).

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
systemctl status fail2ban easy-waf-hostd
```

From another host (with API token): `GET /api/v1/integrations/fail2ban` on the management listener (LAN CIDR only).
