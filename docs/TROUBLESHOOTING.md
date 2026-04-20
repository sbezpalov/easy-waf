# Troubleshooting

Документ соответствует ветке релиза **1.0.0** (см. [`VERSION`](../VERSION)).

## `systemctl`: нет юнита `crowdsec.service` / `crowdsec-haproxy-spoa-bouncer.service`

Пакеты не ставились (например **`EASY_WAF_INSTALL_CROWDSEC=0`**, сбой packagecloud или не **dnf/apt**). По умолчанию **`scripts/install.sh`** ставит CrowdSec и SPOA bouncer на dnf/apt; см. [CROWDSEC.md](CROWDSEC.md).

После установки пакеты есть, а юниты могут быть **disabled** до явного запуска LAPI: **`sudo bash scripts/crowdsec-bootstrap-lapi.sh`** или **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 bash scripts/install.sh`**.

## Dashboard: все сервисы в блоке «Core services» = `unknown`

API вызывает **`/usr/bin/systemctl show -p ActiveState`** (и при необходимости **`is-active`**) от пользователя **`easy-waf`**.

1. Убедитесь, что на хосте установлен **актуальный** `easy-waf-api` после `git pull` и **`systemctl restart easy-waf-api`** (см. [OPERATIONS.md](OPERATIONS.md) — UI встроен в бинарник).
2. Проверьте от имени `easy-waf`: `sudo -u easy-waf /usr/bin/systemctl show -p ActiveState --value haproxy.service` — должно вывести `active` или `inactive`, не пусто.
3. Если команда недоступна: **SELinux** (`ausearch`, контекст сервиса), **отсутствие `/usr/bin/systemctl`**, или ограничения unit (юнит `easy-waf-api.service` уже содержит `ReadWritePaths=/run` для D-Bus).

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

## HAProxy: `Permission denied` on `/var/lib/easy-waf/haproxy/haproxy.cfg`

HAProxy runs as user `haproxy`; easy-waf files are owned by `easy-waf:easy-waf` (mode `0750` on state subdirs). The `haproxy` user must be in the **`easy-waf`** group to read the live config and cert trees.

**Quick fix (from repo root, as root):**

```bash
sudo bash scripts/fix-haproxy-easy-waf-dropin.sh
```

This script:

1. Adds `haproxy` to the `easy-waf` group (`usermod -aG`) when needed  
2. Writes **`/etc/systemd/system/haproxy.service.d/easy-waf.conf`** so HAProxy loads only the generated **`haproxy.cfg`**  
3. Ensures **`/run/haproxy/`** exists (stats socket; **`/etc/tmpfiles.d/easy-waf-haproxy.conf`** for reboots)  
4. Applies SELinux file contexts (**`haproxy_var_lib_t`**) via **`scripts/lib/selinux-easy-waf-haproxy.sh`**  
5. Runs **`systemctl daemon-reload`**

After the script: **`sudo systemctl restart haproxy`** (needed so `haproxy` picks up the new supplementary group).

**Manual SELinux fix (if `ausearch` shows `denied`):**

```bash
sudo EASY_WAF_STATE_DIR=/var/lib/easy-waf bash scripts/lib/selinux-easy-waf-haproxy.sh
```

**Full reinstall** also runs the above when the `haproxy` binary is present: **`sudo bash scripts/install.sh`**.

## HAProxy: `Binding … haproxy.cfg:5` for frontend `GLOBAL` / start exits 1

Line **5** in the generated config is usually **`stats socket /run/haproxy/easy-waf-admin.sock`**. **`haproxy -c`** does not create that Unix socket, so the check can pass while **`ExecStart`** fails if **`/run/haproxy`** is missing, not owned by **`haproxy`**, or a stale **`easy-waf-admin.sock`** is left behind.

**Fix:** run a current **`scripts/fix-haproxy-easy-waf-dropin.sh`** from the repo (it writes **`easy-waf.conf`** with **`ExecStartPre=+/bin/mkdir …`** — the **`+`** runs those steps **as root** because the stock **`haproxy.service`** uses **`User=haproxy`**, and unprivileged **`ExecStartPre`** cannot **`chown`** under **`/run`**) and removes legacy **`50-easy-waf.conf`**), then **`sudo systemctl daemon-reload && sudo systemctl restart haproxy`**.

Manual one-off:

```bash
sudo install -d -o haproxy -g haproxy -m 0755 /run/haproxy
sudo rm -f /run/haproxy/easy-waf-admin.sock
sudo systemctl restart haproxy
```

## HAProxy: `cannot bind UNIX socket (Permission denied)` (stats socket)

The default stats socket path is **`/run/haproxy/easy-waf-admin.sock`** (under **`/run/haproxy`**, **`haproxy_var_run_t`** on RHEL/Alma). If settings still point at **`/var/lib/easy-waf/haproxy/admin.sock`**, update and Apply:

```bash
curl -fsS -X PATCH "http://127.0.0.1:8000/api/v1/settings" \
  -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"haproxy_stats_socket_path":"/run/haproxy/easy-waf-admin.sock"}'
```

Then **Apply** from the UI (or **`easy-waf-admin apply-edge`**) to regenerate **`haproxy.cfg`**.

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

## Collecting diagnostics (support)

1. **From the UI (fast):** Dashboard → **Download diagnostics** — confirms that system info and logs are collected with **masked secrets**, then downloads a `.tar.gz` built by the API (user `easy-waf`). Some host probes may be incomplete without root; see [DIAGNOSTICS.md](DIAGNOSTICS.md).
2. **From the API:** `POST /api/v1/diagnostics/bundle` (authenticated session) — same archive as the button; response is `application/gzip` with `Content-Disposition: attachment`.
3. **Full bundle on the appliance (recommended for support):** run as **root**:
   - After install: `sudo /usr/sbin/easy-waf-diagnostics`
   - From repo: `sudo bash scripts/diagnostics.sh`
   - Output by default: `/tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz`

Details, layout, and what is **not** included: [DIAGNOSTICS.md](DIAGNOSTICS.md).

