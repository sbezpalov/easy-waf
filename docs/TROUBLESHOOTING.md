# Troubleshooting

Документ соответствует ветке релиза **1.0.0-rc1** (см. [`VERSION`](../VERSION)).

## `$'\r': command not found` when running a `*.sh` script

The file has **Windows CRLF** line endings. On the appliance:

```bash
sed -i 's/\r$//' scripts/lib/pg-hba-easywaf.sh
```

Or re-clone / `git pull` after fixing `.gitattributes` and run `git add --renormalize . && git commit` on the dev machine. Repo expects **LF** for all `scripts/**/*.sh` (see [README.md](../README.md)).

## PostgreSQL: `FATAL: Ident authentication failed for user "easywaf"`

Default **pg_hba.conf** on some Alma/RHEL images matches **TCP** `127.0.0.1` with **`ident`**, while easy-waf uses **password** in `DATABASE_URL`. First matching rule wins.

**Fix (from repo root, as root):**

```bash
sudo bash scripts/lib/pg-hba-easywaf.sh
```

Or re-run **`sudo bash scripts/install.sh`** (idempotent; inserts `scram-sha-256` for `easywaf` / DB `easywaf` before generic `host` lines, then reloads PostgreSQL).

Then: `sudo systemctl restart easy-waf-api easy-waf-acmed`.

## PostgreSQL: `password authentication failed for user "easywaf"` (SQLSTATE 28P01)

The password in **`DATABASE_URL`** in **`/etc/easy-waf/easy-waf.env`** does not match **`ALTER USER easywaf`** in the cluster (common after **`scripts/lib/db-password.sh`** rotation or a manual password change).

**Fix:** align credentials — e.g. `sudo -u postgres psql -c "ALTER USER easywaf PASSWORD '…';"` and update **`DATABASE_URL`**, or restore the password from backup. A full **configuration** wipe does **not** reset the DB role password; see [`docs/ADMIN-CLI.md`](ADMIN-CLI.md) **`reset-appliance`** only for app data / HAProxy state / UI users in PostgreSQL tables.

## `systemctl start easy-waf-api` fails immediately (exit 1)

1. Logs: `sudo journalctl -u easy-waf-api -n 50 --no-pager` (often `DATABASE_URL` missing, DB down, or bad env file).
2. **Listen addresses:** set `EASY_WAF_LISTEN_HTTP` / `EASY_WAF_LISTEN_HTTPS` in `/etc/easy-waf/easy-waf.env` (defaults **8000** / **8443** are built into the binary if unset). The systemd unit must **not** pass literal `${VAR:-default}` in `ExecStart` on some hosts — use the stock [`packaging/systemd/easy-waf-api.service`](../packaging/systemd/easy-waf-api.service) (`ExecStart=/usr/sbin/easy-waf-api` only; listen ports and `EASY_WAF_STATE_DIR` from `easy-waf.env`), then `sudo systemctl daemon-reload`. Logs: `sudo journalctl -u easy-waf-api -b -o cat --no-pager | tail -30`.
3. If `DATABASE_URL` uses `127.0.0.1`, ensure PostgreSQL is running: `systemctl status postgresql` (or `postgresql-*` on some distros). Fresh **`install.sh`** installs local PostgreSQL by default; use **`EASY_WAF_INSTALL_POSTGRES=0`** only when the DB is external — then `postgresql.service` may not exist on the host.

## `go build`: `open dist/easy-waf-api: permission denied`

`dist/` or binaries were created as **root** (e.g. `sudo bash scripts/install.sh` built from source). Either:

```bash
sudo chown -R "$(id -un):$(id -gn)" dist
go mod tidy && make build
```

Or remove and rebuild: `sudo rm -rf dist && make build`. Newer **`install.sh`** runs **`chown` on `dist/`** to `SUDO_USER` after a root build so this should not recur.

## `dnf install` fails on `fail2ban` (AlmaLinux 10 / RHEL 10)

**fail2ban** is often only in **EPEL**, not in the default repos. The installer now installs **haproxy, firewalld, nginx** first, then tries **fail2ban**, then **`dnf install epel-release`** and fail2ban again. If it still fails, install manually:

```bash
sudo dnf install -y epel-release
sudo dnf install -y fail2ban fail2ban-firewalld
sudo systemctl enable --now fail2ban
```

## Management UI returns 403 / “management access denied”

- Your client IP is outside **`management_allowed_cidrs`** (see `GET /api/v1/settings` from an allowed host, or fix DB/settings).
- Emergency: **`easy-waf-admin reset-control-panel-access`** or **`EASY_WAF_BYPASS_MGMT_ACL=1`** — see [ADMIN-CLI.md](ADMIN-CLI.md).

## HAProxy fails to reload

1. `sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg`
2. Compare with last good revision under `/var/lib/easy-waf/revisions/`.
3. Use UI **Rollback** or `restore.sh`.

## Certificate issuance fails

- Check DNS points to this host for HTTP-01.
- For DNS-01, verify provider credentials and API reachability.
- Use staging mode first.

## CrowdSec / SPOE errors

- Validate SPOE file path in `haproxy.cfg`.
- Confirm engine name matches SPOE agent section.
- Restart bouncer after LAPI key rotation.

## SELinux denials

- `ausearch -m avc -ts recent` and adjust fcontext or booleans as documented in SECURITY.md.
