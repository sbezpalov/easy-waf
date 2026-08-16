# Operations (edge HAProxy + state)

This complements [QUICKSTART.md](QUICKSTART.md) with day‑2 tasks: inspecting generated config, manual validation, and toggles used during debugging.

**Version:** [`VERSION`](../VERSION) — **1.3.0**.

## Layout (defaults)

| Artifact | Path |
|----------|------|
| State directory | `/var/lib/easy-waf` (`EASY_WAF_STATE_DIR`) |
| Generated HAProxy config | `$STATE/haproxy/haproxy.cfg` |
| Generated TLS crt-list | `$STATE/haproxy/crt-list.txt` |
| IP block map (when used) | `$STATE/haproxy/ip_blacklist.map` (from settings) |
| Artifact revisions | `$STATE/revisions/artifacts-*/manifest.json` + checksum-verified file copies |
| Config preview / legacy rollback | `$STATE/revisions/haproxy-<sha12>.cfg` |

Settings also store `haproxy_config_path` / `haproxy_binary` — apply writes to the configured path and runs `haproxy -c` before reload.

Apply and rollback serialize through a PostgreSQL advisory lock shared by the
API and ACME worker. The generated config, crt-list, IP maps, blocked-UA map,
and GeoIP maps are treated as one revision. If validation, promotion, reload,
or revision bookkeeping fails, the previous set is restored; after a failed
post-promotion reload, the restored config is reloaded when a previous live
revision exists.

## Manual check before reload

The apply pipeline already runs:

```bash
haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg
```

To debug without applying from the API:

```bash
sudo /usr/sbin/haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg
```

Fix template/data issues, then use the UI **Apply** or your orchestration.

## Post-upgrade smoke test

CI proves the code builds, lints, passes unit tests and that golden configs survive `haproxy -c`. It cannot prove anything about *this* appliance: a real PostgreSQL with your migrations applied, a real HAProxy reload with your applications, the systemd units as installed, and the deltas an upgrade brings to a host that already ran an older version.

```bash
sudo bash scripts/smoke-appliance.sh
```

Run it on the pilot host first ([DEV_HOST.md](DEV_HOST.md)), then on production after each upgrade. It is read-mostly: the only state-changing step is `POST /api/v1/apply` — what an operator does anyway — and, when you pass a database file, a GeoIP upload. Backup/restore stays out; that is the destructive [`scripts/test-backup-restore.sh`](../scripts/test-backup-restore.sh).

What it checks, and why each one is here:

| Check | Catches |
|---|---|
| `easy-waf-{hostd,api,acmed}` active; `easy-waf-admin doctor` | services that did not come back after the upgrade; storage, PostgreSQL, schema, GeoIP freshness, certificate expiry |
| `ProtectHome` on the broker unit | units not reloaded — with `ProtectHome=true`, `/home` is invisible to the broker and SSH key management silently cannot write |
| `EASY_WAF_ADMIN_TOKEN` length | 1.2.1 ignores a token under 24 characters; automation using a short one starts getting **401** |
| `GET /api/v1/status`, `/applications` | database reachable and migrations applied |
| `POST /api/v1/apply` | 1.2.1 re-validates application fields at render time and **fails closed**, naming the application — a row stored before those validators existed shows up here |
| `haproxy -c` on the live config, `haproxy` still active | a reload that failed after apply |
| `<state>/geoip` ownership | a root-owned directory (left by an older `update-geoip-db.sh` cron run) that makes UI uploads fail |
| optional `EASY_WAF_SMOKE_MMDB` | the GeoLite2 upload path end to end |
| optional `EASY_WAF_SMOKE_USER`/`_PASSWORD` | that sign-out really revokes the session (`/auth/me` 200 → logout → 401) |

It also prints a note when generated backend names contain `-`: 1.3.0 stopped collapsing that character, so dashboards keyed on the old HAProxy names need updating.

Exit code is non-zero if any check fails; `EASY_WAF_SMOKE_SKIP_APPLY=1` leaves the edge untouched.

## Package lifecycle: what `remove` and `purge` actually do

Easy Home WAF ships as a Debian package ([ADR 0001](adr/0001-packaging-and-installer.md)),
so `dpkg -l easy-waf` answers "which version is on this appliance" and removal is
a defined operation rather than a hunt for files.

| Command | Binaries and units | `/etc/easy-waf` | `/var/lib/easy-waf` | PostgreSQL | nftables |
|---|---|---|---|---|---|
| `apt install ./easy-waf_X.Y.Z_amd64.deb` | replaced | conffile preserved | untouched | untouched | untouched |
| `apt remove easy-waf` | removed; services stopped and disabled | kept | kept | untouched | untouched |
| `apt purge easy-waf` | removed | **deleted** | kept | untouched | untouched |

Three consequences worth knowing before you need them:

- **`purge` does not delete appliance state.** `/var/lib/easy-waf` holds TLS
  private keys, certificates issued through rate-limited ACME accounts, the JWT
  signing secret and the revision history used for rollback. dpkg cannot tell
  "done with this host" from "reinstalling", so `postrm` prints the path and the
  command instead of guessing. Remove it yourself when you are sure:
  `tar -czf easy-waf-state.tar.gz /var/lib/easy-waf && rm -rf /var/lib/easy-waf`.
- **The database survives everything.** The package never created the `easywaf`
  role or database, so it never drops them. Reinstalling onto the same host picks
  up the existing schema; migrations are applied by the API on start.
- **The `easy-waf` account is kept on purge**, so the remaining state does not end
  up owned by a recycled UID. Use `deluser --system easy-waf` after removing the
  state directory.

Upgrading an appliance that was installed by the script, before packaging existed:
`install.sh` renames any `/etc/systemd/system/easy-waf-*.service` it finds to
`*.replaced-by-package`. Those files override the packaged units in `/lib`, and
left in place they make an upgrade look applied while systemd keeps starting the
old definition. If you removed them by hand, run `systemctl daemon-reload`.

## Environment toggles (service unit)

| Variable | Effect |
|----------|--------|
| `EASY_WAF_SKIP_VALIDATE` | If set (non-empty), skip `haproxy -c` during apply — **only** for broken lab environments; never in production. |
| `EASY_WAF_SKIP_RELOAD` | If set, write the artifact set and revision but **do not** reload HAProxy (test/debug only). |

Restart `easy-waf-api` after changing these in `/etc/easy-waf/easy-waf.env`.

## Updating code after `git pull` (why the UI “doesn’t show changes”)

The web UI is **embedded in the `easy-waf-api` binary** at build time (`go:embed` → `internal/webui/dist`). Changes to `index.html` and new API routes **will not appear** until you rebuild the API and restart the service.

On a machine with the repo (as root or with rights to `make install`):

```bash
cd /path/to/easy-waf
git pull
make clean && make build && make test   # or: go build -o dist/easy-waf-api ./cmd/easy-waf-api …
sudo install -m 0755 dist/easy-waf-api /usr/sbin/easy-waf-api
sudo install -m 0755 dist/easy-waf-acmed /usr/sbin/easy-waf-acmed   # if acmed changed
sudo systemctl restart easy-waf-api.service
# if needed: sudo systemctl restart easy-waf-acmed.service
```

Hard-refresh the browser: **Ctrl+F5** (bypass cache). An old `easy-waf-api` process keeps serving the old embed until restart.

### Dashboard: “Core services (systemd)” empty or “unavailable”

1. **Sign in to the UI** and open the **Dashboard** tab. The request uses JWT; with an expired session the dashboard may only partially load — sign in again.
2. **Check the API response on the host** using the enabled listener from `/etc/easy-waf/easy-waf.env`. The bootstrap certificate covers `127.0.0.1`, so the default local HTTPS check can verify it directly:
   ```bash
   curl --cacert /var/lib/easy-waf/secrets/management.crt -sS -X POST \
     "https://127.0.0.1:8443/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -H "X-Requested-With: XMLHttpRequest" \
     -d '{"username":"YOUR_LOGIN","password":"YOUR_PASSWORD"}'
   ```
   Copy `token` from the JSON, then:
   ```bash
   curl --cacert /var/lib/easy-waf/secrets/management.crt -sS \
     -o /tmp/svc.json -w "HTTP %{http_code}\n" \
     -H "Authorization: Bearer TOKEN" \
     "https://127.0.0.1:8443/api/v1/system/services"
   cat /tmp/svc.json
   ```
   - **404** — old `easy-waf-api` on disk without the route: rebuild and reinstall the binary, **`systemctl restart easy-waf-api`**, then **Ctrl+F5** in the browser.
   - **401 / 403** — wrong password or **required initial password change**; change the password in the UI, then refresh the dashboard.
   - **200** with a `services` array — API is fine; if the table is still missing in the browser, open DevTools → **Network** → `system/services` (cache, wrong origin, extension blocking).
3. **`easy-waf-api` unit**: current template in the repo is `packaging/systemd/easy-waf-api.service` (for `systemctl show` from the API process, **`/run`** must be in `ReadWritePaths`). After editing the unit: **`systemctl daemon-reload`** and **restart**.

Changes only in **`scripts/install.sh`** (e.g. `ensure_haproxy_systemd_enabled`) on an already installed system: either re-run the relevant fragment manually (`sudo systemctl enable haproxy.service`), or re-run the installer carefully around already configured files — see [DEPLOYMENT.md](DEPLOYMENT.md).

## Profiles vs generated rules

Security profiles (`internal/profiles`) drive per‑application behaviour in the generated config:

- **Enabled frontends `fe_http` / `fe_https`:** the same per-host security block covers paths, methods, IP lists, GeoIP, bot/User-Agent checks, basic WAF, restricted paths, and CrowdSec SPOE. ACME HTTP-01 challenges are excluded on port 80.
- **Each backend:** `timeout connect` / `timeout server`, keep-alive vs server-close, **stick-table** + `http_req_rate(10s)` vs `RateLimitBurst`, WebSocket tunnel and health checks as before.

See [SECURITY_PROFILES.md](SECURITY_PROFILES.md).

## Nginx on the edge

The product does **not** require a separate Nginx in front of HAProxy for the MVP: HTTP‑01 challenges are served via HAProxy → `bk_acme` → easy‑wafd. A standalone Nginx is optional for unrelated sites on the same host.
