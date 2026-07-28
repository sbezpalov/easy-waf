# Operations (edge HAProxy + state)

This complements [QUICKSTART.md](QUICKSTART.md) with day‑2 tasks: inspecting generated config, manual validation, and toggles used during debugging.

**Version:** [`VERSION`](../VERSION) — **1.0.0**.

## Layout (defaults)

| Artifact | Path |
|----------|------|
| State directory | `/var/lib/easy-waf` (`EASY_WAF_STATE_DIR`) |
| Generated HAProxy config | `$STATE/haproxy/haproxy.cfg` |
| Generated TLS crt-list | `$STATE/haproxy/crt-list.txt` |
| IP block map (when used) | `$STATE/haproxy/ip_blacklist.map` (from settings) |
| Config revisions (snapshots) | `$STATE/revisions/haproxy-<sha12>.cfg` |

Settings also store `haproxy_config_path` / `haproxy_binary` — apply writes to the configured path and runs `haproxy -c` before reload.

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

## Environment toggles (service unit)

| Variable | Effect |
|----------|--------|
| `EASY_WAF_SKIP_VALIDATE` | If set (non-empty), skip `haproxy -c` during apply — **only** for broken lab environments; never in production. |
| `EASY_WAF_SKIP_RELOAD` | If set, write config and revision but **do not** reload HAProxy (audit-only / dry write). |

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
2. **Check the API response on the host** (use the port from `EASY_WAF_LISTEN_HTTP` in `/etc/easy-waf/easy-waf.env`, often `8000`):
   ```bash
   curl -sS -X POST "http://127.0.0.1:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -H "X-Requested-With: XMLHttpRequest" \
     -d '{"username":"YOUR_LOGIN","password":"YOUR_PASSWORD"}'
   ```
   Copy `token` from the JSON, then:
   ```bash
   curl -sS -o /tmp/svc.json -w "HTTP %{http_code}\n" \
     -H "Authorization: Bearer TOKEN" \
     "http://127.0.0.1:8000/api/v1/system/services"
   cat /tmp/svc.json
   ```
   - **404** — old `easy-waf-api` on disk without the route: rebuild and reinstall the binary, **`systemctl restart easy-waf-api`**, then **Ctrl+F5** in the browser.
   - **401 / 403** — wrong password or **required initial password change**; change the password in the UI, then refresh the dashboard.
   - **200** with a `services` array — API is fine; if the table is still missing in the browser, open DevTools → **Network** → `system/services` (cache, wrong origin, extension blocking).
3. **`easy-waf-api` unit**: current template in the repo is `packaging/systemd/easy-waf-api.service` (for `systemctl show` from the API process, **`/run`** must be in `ReadWritePaths`). After editing the unit: **`systemctl daemon-reload`** and **restart**.

Changes only in **`scripts/install.sh`** (e.g. `ensure_haproxy_systemd_enabled`) on an already installed system: either re-run the relevant fragment manually (`sudo systemctl enable haproxy.service`), or re-run the installer carefully around already configured files — see [DEPLOYMENT.md](DEPLOYMENT.md).

## Profiles vs generated rules

Security profiles (`internal/profiles`) drive per‑application behaviour in the generated config:

- **Frontend `fe_https`:** path blocks from the profile, scoped by `Host` (plus global `/.git` and `/.env`), extra blocked methods, IP block map, CrowdSec SPOE.
- **Each backend:** `timeout connect` / `timeout server`, keep-alive vs server-close, **stick-table** + `http_req_rate(10s)` vs `RateLimitBurst`, WebSocket tunnel and health checks as before.

See [SECURITY_PROFILES.md](SECURITY_PROFILES.md).

## Nginx on the edge

The product does **not** require a separate Nginx in front of HAProxy for the MVP: HTTP‑01 challenges are served via HAProxy → `bk_acme` → easy‑wafd. A standalone Nginx is optional for unrelated sites on the same host.
