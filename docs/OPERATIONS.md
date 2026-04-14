# Operations (edge HAProxy + state)

This complements [QUICKSTART.md](QUICKSTART.md) with day‑2 tasks: inspecting generated config, manual validation, and toggles used during debugging.

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

## Profiles vs generated rules

Security profiles (`internal/profiles`) drive per‑application behaviour in the generated config:

- **Frontend `fe_https`:** path blocks from the profile, scoped by `Host` (plus global `/.git` and `/.env`), extra blocked methods, IP block map, CrowdSec SPOE.
- **Each backend:** `timeout connect` / `timeout server`, keep-alive vs server-close, **stick-table** + `http_req_rate(10s)` vs `RateLimitBurst`, WebSocket tunnel and health checks as before.

See [SECURITY_PROFILES.md](SECURITY_PROFILES.md).

## Nginx on the edge

The product does **not** require a separate Nginx in front of HAProxy for the MVP: HTTP‑01 challenges are served via HAProxy → `bk_acme` → easy‑wafd. A standalone Nginx is optional for unrelated sites on the same host.
