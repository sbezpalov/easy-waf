# Security profiles (MVP)

| Profile | Rate (RPS / burst) | Server timeout | Path blocks | Notes |
|---------|-------------------|----------------|-------------|--------|
| `balanced` | 50 / 100 | 50s | default probes | General home apps |
| `strict` | 20 / 40 | 30s | extended | Hardened |
| `trusted-lan` | 200 / 400 | 120s | minimal | High trust / LAN-heavy |
| `public-app` | 30 / 60 | 60s | default | Internet-exposed generic |
| `php-app` | 50 / 100 | 50s | default | PHP apps: blocks multipart, 32 MiB body limit |
| `home-assistant` | 40 / 80 | 3600s | default | Long-lived WS/SSE |
| `none` | 500 / 1000 | 300s | *(none)* | High limits; combine with per-app toggles |
| `custom` | 50 / 100 | 50s | default | Alias of balanced numerics; tuning via toggles |

Implementation: profile metadata lives in `internal/profiles`. The HAProxy template (`internal/haproxy/render.go`) applies **per published application**:

- **Enabled frontends (`fe_http` / `fe_https`):** when the app’s `path_acl_enabled` / `method_filter_enabled` toggles are on, `BlockPaths` and `ExtraBlockedMethods` from the profile are enforced for that host; other layers (WAF, bot checks, IPBL, GeoIP, CrowdSec) are also gated by per-app toggles (see [APPLICATION_SECURITY.md](APPLICATION_SECURITY.md)).
- **Backend:** `ConnectTimeout`, `ServerTimeout`, `HTTPKeepAlive`, optional stick-table rate limit vs **`RateLimitBurst`** (with optional per-app overrides), plus WebSocket/health/`server` lines.

## Request bodies

HAProxy does not inspect request bodies here, so these rules work from headers. Only `php-app` sets them by default; any application can set them with `max_body_bytes_override`, `block_multipart_override` and `multipart_allowed_paths`.

- **Multipart block:** a `multipart/*` request gets **415**, except on `multipart_allowed_paths`. `/upload` allows that path and what is below it, not `/upload.php`. Those paths remain exposed, and a request path containing `..` never counts as allowed. Sources on the IP allowlist skip this and the limit, like every other per-application rule.
- **Body limit:** a declared `Content-Length` over the limit gets **413**. HAProxy cannot count a streamed body, so a `POST`, `PUT` or `PATCH` without `Content-Length`, and anything with `Transfer-Encoding`, gets **411**. Check chunked clients (`git`, some WebDAV and backup tools), and an empty `POST` with no `Content-Length: 0`, before turning it on. Other methods without a declared length over HTTP/2 are not limited.

This narrows what reaches a vulnerable parser, such as PHP's. **It is not a fix:** patch the backend.

## Per-application security layers

| Layer | Role | When to enable |
|-------|------|----------------|
| Certificate | TLS identity for the public host | Always (pick in UI) |
| Security profile | Rate defaults, path lists, methods, timeouts | Pick posture per app (`balanced`, `strict`, …) |
| Rate limiting | Stick-table abuse control | Almost always on in production |
| Path ACL | Block common probe paths from profile | On unless you trust all paths (e.g. some LAN cases) |
| Method filter | Block TRACE / CONNECT / … from profile | Recommended on |
| Basic WAF | SQLi / XSS / traversal heuristics | On for internet-facing apps |
| Bot protection | Empty UA + optional substring map | On unless broken clients need empty UA |
| IP blacklist | Global map, per-app toggle | On when IPBL is maintained |
| IP allowlist | Trusted bypass (global map + per-app) | When you need break-glass trusted IPs |
| GeoIP | Per-app country allow/deny via batch map | When you need country policy for one hostname |
| CrowdSec | SPOE group per request, 403 on a decision other than `allow` (fails open if the bouncer is down) | When CrowdSec is deployed |
| Restricted paths | Per-prefix CIDR LAN walls | Sensitive paths (e.g. `/api`) |

## Mode presets (application scope)

| Preset | Summary |
|--------|---------|
| **Full protection** | All toggles on including GeoIP; profile forced to **strict** |
| **Balanced** | Default: all on except GeoIP; profile **balanced** |
| **Trusted LAN** | Path ACL + basic WAF + bot off; profile **trusted-lan** |
| **Reverse proxy only** | All protection toggles off — **routing + TLS only** for that app |
| **Custom** | Manual toggles |

> **Warning — `reverse-proxy-only`:** This mode is for **debugging only**. It disables **all** WAF-style protections for the selected application (no rate limit, no CrowdSec hook, no IPBL/WAF/bot/geo for that host). Do **not** use it for production-facing hostnames.

`GeoDefaultDeny` on the `Profile` struct remains reserved for legacy global behaviour; per-app GeoIP uses `security.geoip_policy` and `security.geoip_country_list`.
