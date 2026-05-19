# Fail2Ban integration

Fail2Ban protects **SSH** (and optional jails) on the appliance. Easy WAF installs the package via `scripts/install.sh` when available (EPEL on Alma/RHEL).

## Management API (UI)

Authenticated session (same JWT + `X-Requested-With` as other mutating routes):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/integrations/fail2ban` | Daemon ping + jail list with banned IPs |
| `GET` | `/api/v1/integrations/fail2ban/jails/{jail}` | One jail status |
| `POST` | `/api/v1/integrations/fail2ban/unban` | Body `{ "jail": "sshd", "ip": "203.0.113.1" }` |

Audit: explicit `fail2ban.unban` plus HTTP audit category **fail2ban**.

## Permissions

`easy-waf-api` runs as user **`easy-waf`**. Reading status and unbanning requires **`fail2ban-client`**, which is usually root-only.

On install, `scripts/install.sh` writes **`/etc/sudoers.d/easy-waf-fail2ban`** (validated with `visudo -c`) allowing:

- `fail2ban-client status`
- `fail2ban-client status <jail>`
- `fail2ban-client set <jail> unbanip <ip>`

The API client retries with **`sudo -n`** when the direct call returns permission denied. Optional: set **`EASY_WAF_FAIL2BAN_USE_SUDO=1`** in `/etc/easy-waf/easy-waf.env` to always use sudo.

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
```

From another host (with API token): `GET /api/v1/integrations/fail2ban` on the management listener (LAN CIDR only).
