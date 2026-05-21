# Troubleshooting

Документ соответствует ветке релиза **1.0.0** (см. [`VERSION`](../VERSION)).

## `systemctl`: нет юнита `crowdsec.service` / SPOA bouncer

Пакеты не ставились (например **`EASY_WAF_INSTALL_CROWDSEC=0`**, сбой packagecloud). По умолчанию **`scripts/install.sh`** ставит CrowdSec и SPOA bouncer через **apt**; см. [CROWDSEC.md](CROWDSEC.md).

**Имя systemd-юнита SPOA (важно):** пакет **`crowdsec-haproxy-spoa-bouncer`**, а сервис на Ubuntu 24.04 — **`crowdsec-spoa-bouncer.service`** (не `crowdsec-haproxy-spoa-bouncer.service`). После `apt install`:

```bash
systemctl enable --now crowdsec-spoa-bouncer.service
systemctl status crowdsec-spoa-bouncer.service
```

Конфиг bouncer: `/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml`.

После установки пакеты есть, а юниты могут быть **disabled** до явного запуска LAPI: **`sudo bash scripts/crowdsec-bootstrap-lapi.sh`** или **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 bash scripts/install.sh`** (перерегистрирует bouncers **`easy-waf-api`** / **`easy-waf-spoa`** и ключ в **`/etc/easy-waf/easy-waf.env`**).

## Dashboard: все сервисы в блоке «Core services» = `unknown`

API вызывает **`/usr/bin/systemctl show -p ActiveState`** (и при необходимости **`is-active`**) от пользователя **`easy-waf`**.

1. Убедитесь, что на хосте установлен **актуальный** `easy-waf-api` после `git pull` и **`systemctl restart easy-waf-api`** (см. [OPERATIONS.md](OPERATIONS.md) — UI встроен в бинарник).
2. Проверьте от имени `easy-waf`: `sudo -u easy-waf /usr/bin/systemctl show -p ActiveState --value haproxy.service` — должно вывести `active` или `inactive`, не пусто.
3. Если команда недоступна: **AppArmor** / отсутствие **`/usr/bin/systemctl`**, или ограничения unit (юнит `easy-waf-api.service` уже содержит `ReadWritePaths=/run` для D-Bus).

## `$'\r': command not found` when running a `*.sh` script

The file has **Windows CRLF** line endings. On the appliance:

```bash
sed -i 's/\r$//' scripts/lib/pg-hba-easywaf.sh
```

Or re-clone / `git pull` after fixing `.gitattributes` and run `git add --renormalize . && git commit` on the dev machine. Repo expects **LF** for all `scripts/**/*.sh` (see [README.md](../README.md)).

## PostgreSQL: `FATAL: Ident authentication failed for user "easywaf"`

Default **pg_hba.conf** on some PostgreSQL installs matches **TCP** `127.0.0.1` with **`ident`/`peer`**, while easy-waf uses **password** in `DATABASE_URL`. First matching rule wins.

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

## fail2ban not installed

On **Ubuntu 24.04**, **fail2ban** is in the default repositories:

```bash
sudo apt-get update
sudo apt-get install -y fail2ban
sudo systemctl enable --now fail2ban
```

Re-run **`sudo bash scripts/install.sh`** so **`easy-waf-hostd`** is installed and legacy socket/sudoers drop-ins are removed.

## Fail2Ban UI: empty jails / bad gateway / permission denied

The API does **not** call `fail2ban-client` as **`easy-waf`** and does **not** use `sudo` (`NoNewPrivileges=true`). Status and unban go through **`easy-waf-hostd`**, which runs **`fail2ban-client`** as root.

Check (from repo root on the appliance):

```bash
systemctl status easy-waf-hostd fail2ban
ls -la /run/easy-waf/hostd.sock
sudo fail2ban-client ping    # expect: pong
sudo fail2ban-client status
```

If hostd is down or the socket is missing, restart after rebuild:

```bash
sudo systemctl restart easy-waf-hostd easy-waf-api
```

Old installs may still have **`/etc/sudoers.d/easy-waf-fail2ban`** or fail2ban socket drop-ins; **`install.sh`** removes them. Direct `sudo -u easy-waf fail2ban-client` is **not** the supported check on current releases.

See [FAIL2BAN.md](FAIL2BAN.md).

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
4. Runs **`systemctl daemon-reload`**

After the script: **`sudo systemctl restart haproxy`** (needed so `haproxy` picks up the new supplementary group).

**AppArmor:** on Ubuntu the stock HAProxy profile is usually sufficient. If you see `DENIED` in `/var/log/syslog`, run **`aa-status`** and review **`/etc/apparmor.d/usr.sbin.haproxy`** if needed.

**Full reinstall** also runs the drop-in when the `haproxy` binary is present: **`sudo bash scripts/install.sh`**.

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

The default stats socket path is **`/run/haproxy/easy-waf-admin.sock`**. If **`global_settings_json`** still has the legacy **`…/haproxy/admin.sock`** under the state dir, **Apply** / **`apply-edge`** now rewrites it in the **rendered** `haproxy.cfg` to **`/run/haproxy/easy-waf-admin.sock`** automatically (no DB patch required for that exact legacy path). For any other custom path, update settings and Apply:

```bash
curl -fsS -X PATCH "http://127.0.0.1:8000/api/v1/settings" \
  -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"haproxy_stats_socket_path":"/run/haproxy/easy-waf-admin.sock"}'
```

Then **Apply** from the UI (or **`easy-waf-admin apply-edge`**) to regenerate **`haproxy.cfg`**.

## HAProxy: port 80 / 443 not reachable (nftables)

HAProxy listens on **`*:80`** and **`*:443`**; if **`ss -tlnp`** shows **`haproxy`** but clients time out, check **`sudo nft list ruleset`** for **`tcp dport { 80, 443 } accept`**.

**Fix:** from the repo on the appliance, **`sudo bash scripts/fix-nftables-edge.sh`**. New installs run this automatically via **`scripts/install.sh`** unless **`EASY_WAF_NFT_EDGE=0`**.

## HAProxy: `bk_acme` / `127.0.0.1:8089` DOWN (connection refused)

`fe_http` routes `/.well-known/acme-challenge/` to **`bk_acme`**, which uses **`server … 127.0.0.1:8089 check`**. **`easy-waf-api`** must be running: it listens on that loopback address by default and serves token files from the ACME webroot (same tree **Lego** uses for HTTP-01). If the API is stopped or the binary predates that listener, HAProxy reports **connection refused** and **`backend bk_acme has no server available`**.

**Fix:** `sudo systemctl start easy-waf-api` (or `restart`) after upgrading. To disable the helper (only if you serve challenges another way), set **`EASY_WAF_ACME_INTERNAL_HTTP=0`** in **`/etc/easy-waf/easy-waf.env`** and restart **`easy-waf-api`**. See [ACME.md](ACME.md).

## HAProxy fails to reload

1. `sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg`
2. Compare with last good revision under `/var/lib/easy-waf/revisions/`.
3. Use UI **Rollback** or `restore.sh`.

## Certificate issuance fails

- Check DNS points to this host for HTTP-01.
- For DNS-01, verify provider credentials and API reachability.
- Use staging mode first.

## `install.sh` seems stuck after “LAPI not ready” / many `apt-get` lines

Older installers retried **`apt-get -f install`** in a loop while LAPI was already up but **`curl -f`** treated **401/405** as failure. Current **`scripts/lib/crowdsec-install.sh`**:

- Detects LAPI with **`crowdsec_lapi_reachable`** (HTTP status or **`cscli lapi status`**).
- **Re-runs** (`crowdsec` already installed): **systemd-only** recovery, ~2 minutes max, with **`waiting for LAPI (n/m)...`** log lines.
- **Fresh install**: one **`apt-get -f`** pass, then the same systemd recovery.

If it still fails: `systemctl status crowdsec`, `journalctl -u crowdsec -n 80`, `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/`, then `sudo bash scripts/crowdsec-bootstrap-lapi.sh`.

## CrowdSec UI: 502 on decisions / install “LAPI decisions check failed”

LAPI bouncers authenticate with **`X-Api-Key: <key>`** ([CrowdSec docs](https://doc.crowdsec.net/docs/local_api/bouncers/)). Wrong header → **403** → UI **502** or install error even when `CROWDSEC_LAPI_KEY` in `easy-waf.env` is correct.

```bash
KEY=$(sudo grep '^CROWDSEC_LAPI_KEY=' /etc/easy-waf/easy-waf.env | cut -d= -f2-)
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: $KEY" 'http://127.0.0.1:8080/v1/decisions?limit=1'
# expect 200
```

After `git pull` + `make build`: reinstall API binary and `sudo systemctl restart easy-waf-api`, or re-run `sudo bash scripts/install.sh` (bootstrap check now uses `X-Api-Key`).

## CrowdSec / SPOE errors

- Validate SPOE file path in `haproxy.cfg`.
- Confirm engine name matches SPOE agent section.
- Restart bouncer after LAPI key rotation.

## AppArmor denials (Ubuntu)

- Run **`aa-status`** and inspect **`/var/log/syslog`** for `apparmor="DENIED"` related to **`haproxy`**.
- Stock Ubuntu profile **`/etc/apparmor.d/usr.sbin.haproxy`** is usually sufficient for reading configs under **`/var/lib/easy-waf`** when **`haproxy`** is in group **`easy-waf`**.
- Do **not** disable AppArmor globally; adjust the profile locally if you use non-standard paths.

## Collecting diagnostics (support)

1. **From the UI (fast):** Dashboard → **Download diagnostics** — confirms that system info and logs are collected with **masked secrets**, then downloads a `.tar.gz` built by the API (user `easy-waf`). Some host probes may be incomplete without root; see [DIAGNOSTICS.md](DIAGNOSTICS.md).
2. **From the API:** `POST /api/v1/diagnostics/bundle` (authenticated session) — same archive as the button; response is `application/gzip` with `Content-Disposition: attachment`.
3. **Full bundle on the appliance (recommended for support):** run as **root**:
   - After install: `sudo /usr/sbin/easy-waf-diagnostics`
   - From repo: `sudo bash scripts/diagnostics.sh`
   - Output by default: `/tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz`

Details, layout, and what is **not** included: [DIAGNOSTICS.md](DIAGNOSTICS.md).

