# Per-application security

Each published application carries a `security` object (see `internal/config/types.go`) with a **mode preset** (`full`, `balanced`, `trusted-lan`, `reverse-proxy-only`, `custom`) and **per-layer toggles**. HAProxy rules are emitted **per application** in `fe_https` in a fixed order (see below).

## Rule order on `fe_https` (per app)

1. Host match (`acl app_<id>_host hdr(host) -i …`)
2. **Allowlist bypass** — `http-request allow` when global IP allowlist is enabled, the app allows it, and the source matches the map (short-circuits further rules for that request in the ruleset phase).
3. **IP blacklist** deny
4. **GeoIP** (per-app map `geoip_app_<id>.map`, built on Apply / IPBL sync when country targets exist)
5. **Bot protection** — empty User-Agent (requires global `block_empty_ua`) and optional blocked UA map (requires global `blocked_user_agents_enabled`)
6. **Basic WAF** — SQLi / XSS / `../` traversal ACLs
7. **Method filter** — `ExtraBlockedMethods` from the selected **profile**
8. **Path ACL** — `BlockPaths` from the profile (`path_beg` denies)
9. **Restricted paths** — per-path CIDR allowlists (always evaluated when configured)
10. **CrowdSec** — `http-request send-spoe-group` when the SPOE filter is loaded and the app has `crowdsec_enabled`

`use_backend` lines follow after all applications.

## Backend (`be_<sanitized_host>`)

1. **Rate limit** — stick-table + `http-request deny … 429` when `rate_limit_enabled` (allowlist sources may bypass 429 when the app enables allowlist check and global IPWL is on)
2. Profile **timeouts** and **keep-alive** mode
3. **WebSocket** tunnel timeout when flagged
4. **Health check** / **server** line

## Mode presets vs toggles

Presets are applied with `POST /api/v1/applications/{id}/security/mode` (see `internal/profiles/modes.go`). `custom` leaves toggles under manual control. After any change, the API normalises `mode` with `DetectMode` from the current toggle vector.

## Use cases

- **Home Assistant on a public IP** — `balanced` (default) + **Restricted paths** on `/api` to LAN CIDRs; optionally enable **GeoIP** with an allow-list of home countries (`custom` + toggles).
- **Debugging a new upstream** — `reverse-proxy-only`: TLS + Host routing only; **no** WAF, CrowdSec, IPBL, or rate limit for that hostname. Intended for short-lived troubleshooting, not production.
- **Internal Zabbix** — `trusted-lan` preset: fewer path probes and no basic WAF/bot heuristics while keeping rate limits and CrowdSec.
- **Nextcloud with GeoIP deny list** — `custom`, enable **GeoIP**, policy `deny`, country list of regions to block; keep other layers as needed.

## API

- `GET /api/v1/security/modes` — preset catalogue for the UI
- `GET|PUT|PATCH /api/v1/applications/{id}/security` — read or update the `security` JSON
- `POST /api/v1/applications/{id}/security/mode` — apply a preset (`{"mode":"…"}`); audited as `app_security_mode_changed` (detail includes `level":"warn"` when switching to `reverse-proxy-only`)
