# Per-application security

Each published application carries a `security` object (see `internal/config/types.go`) with a **mode preset** (`full`, `balanced`, `trusted-lan`, `reverse-proxy-only`, `custom`) and **per-layer toggles**. It also has **`listen_mode`** (see below) for **where** traffic is accepted (`fe_http` / `fe_https`). The HAProxy template emits the same reusable per-application security block on every enabled frontend: IP lists, GeoIP, bot/User-Agent checks, basic WAF, method and path ACLs, restricted paths, and CrowdSec/SPOE. Rate limiting remains in the shared backend and runs once per request.

## Listen mode (protocol)

`listen_mode` is **orthogonal** to `security.mode`: one controls **protocol / publishing**, the other **which protections are on** for that hostname.

| `listen_mode` | `fe_http` (:80) | `fe_https` (:443) | Certificate |
|---------------|-----------------|-------------------|-------------|
| `https_only` (default) | Per-host redirect to HTTPS | Served (TLS) | Required |
| `redirect_to_https` | Same as `https_only` (explicit naming) | Served (TLS) | Required |
| `http_only` | Plain HTTP to backend | Not published | Optional (unused if set) |
| `http_and_https` | Plain HTTP to backend | Served (TLS) | Required |

Notes:

- **`http_only`** means traffic to that host on port 80 is **not encrypted** at the edge — suitable for **LAN**, **IoT**, or **debugging**, not for untrusted networks.
- **`http_only` + `full`** (or `balanced`) is valid: the same enabled security layers apply on HTTP and HTTPS. HTTP remains cleartext, so policy parity does not provide transport confidentiality.
- For **internet-facing** services, prefer **`https_only`** (or `redirect_to_https`).

## Rule order on enabled frontends (per app)

The sequence below is shared by `fe_http` and `fe_https`. On port 80, HAProxy handles `/.well-known/acme-challenge/` before application rules so ACME HTTP-01 is not blocked by WAF or path policy.

1. Host match (`acl app_<id>_host hdr(host) -i …`)
2. **Path allowlist** — when `path_policy.mode` is `allowlist`, any other path is **404**. This runs before the IP allow shortcut, so a trusted source still cannot reach an unpublished path. Profile block lists and restricted paths still apply to paths that are on the list.
3. **Required headers** — `path_policy.rules` may require a header (and an optional value prefix) or an edge token. A miss is **401**. The edge-token header is removed before the backend. Neither value is captured in httplog.
4. **Publication rules** run in configured order before the IP allowlist. See [ordered publication rules](#ordered-publication-rules).
5. **Allowlist bypass** — `http-request allow` when global IP allowlist is enabled, the app allows it, and the source matches the map. This short-circuits subsequent frontend rules.
6. **IP blacklist** deny
7. **GeoIP** (per-app map `geoip_app_<id>.map`, built on Apply from a local Country MMDB when country targets exist). See [country policy behavior](GEOIP.md#country-policies-on-a-publication).
8. **Bot protection** — empty User-Agent (requires global `block_empty_ua`) and optional blocked UA map (requires global `blocked_user_agents_enabled`)
9. **Basic WAF** — SQLi / XSS / `../` traversal ACLs
10. **Method filter** — `ExtraBlockedMethods` from the selected **profile**
11. **Path ACL** — `BlockPaths` from the profile (`path_beg` denies)
12. **Restricted paths** — per-path CIDR allowlists (always evaluated when configured)
13. **Multipart block** — `415` for `multipart/*` outside `multipart_allowed_paths`, when the profile or the app turns it on ([SECURITY_PROFILES.md](SECURITY_PROFILES.md#request-bodies))
14. **Body limit** — `413` over the limit, `411` for a body of undeclared length; headers only, bodies are not inspected
15. **CrowdSec** — `http-request send-spoe-group`, then a 403 for any remediation other than `allow`, when the SPOE filter is loaded and the app has `crowdsec_enabled`

`use_backend` lines follow after all applications.

## Ordered publication rules

Edit **Publication rules** in the advanced application settings. Move rules up or down to set their priority and save the application. If changes are pending, use **Apply HAProxy**. Each publication supports up to 16 rules. Use a unique ID for each rule in the publication.

All specified conditions must match. A methods or source list matches any one of its entries.

| Condition | Behavior |
|---|---|
| Path prefix | Case-sensitive match on the request path as received by HAProxy, excluding the query string. `/api` matches `/api` and its descendants. Use `/` to match every path. |
| Methods | One or more uppercase HTTP methods. |
| Source | IPv4 or IPv6 addresses and CIDRs, using HAProxy's client source after configured trusted-proxy handling. |
| Header | Exact header name, case-insensitive. An optional case-sensitive prefix tests the value. Header conditions are suitable for traffic classification. Keep authentication in the application or an authentication layer. |

| Action | Behavior on a match |
|---|---|
| **Count** | Record the match and evaluate the next rule. |
| **Block** | Record the match and return HTTP 403. |
| **Pass** | Record the match, end the ordered list and continue with the remaining security checks. |

Use Count to observe a new condition before switching it to Block. **Events & audit → Publication rule matches** lists all matching rules for each logged request in evaluation order, with the final HTTP status. A Count match can appear on a successful request or one rejected later. Entries follow HAProxy journal retention and appear when HAProxy writes the request log. The match view shows the host, rule IDs and actions, and excludes client IPs, request targets and header values.

The application API uses the order of the `policy_rules` array. For example, `{"id":"observe-api","action":"count","match":{"path_prefix":"/api","methods":["POST"]}}` is one entry. Omit the field on update to keep the saved list. Send an empty array to clear it. Read the match journal with `GET /api/v1/security/policy-matches?period=24h&limit=200`.

## Backend (`be_<sanitized_host>`)

1. **Rate limit** — stick-table + `http-request deny … 429` when `rate_limit_enabled` (allowlist sources may bypass 429 when the app enables allowlist check and global IPWL is on)
2. **Per-path rate limit** — a separate stick-table per `path_policy` rule with `rate_per_10s`. The longest matching prefix owns the counter.
3. **Server timeout override** — `http-request set-timeout server` for the app and for path rules. HAProxy 2.8 cannot set `timeout client` per request; a requested client timeout raises it for the whole frontend and adds `timeout http-request 10s`. See [HA-MCP.md](HA-MCP.md).
4. Profile **timeouts** and **keep-alive** mode
5. **WebSocket** tunnel timeout when flagged
6. **Health check** / **server** line

## Mode presets vs toggles

Presets are applied with `POST /api/v1/applications/{id}/security/mode` (see `internal/profiles/modes.go`). `custom` leaves toggles under manual control. After any change, the API normalises `mode` with `DetectMode` from the current toggle vector.

## Use cases

- **Home Assistant on a public IP** — profile `home-assistant` with the desired security-mode layers. One publication normally serves the web UI, Companion and API. Restricting `/api` to LAN CIDRs also blocks external `/api/websocket` and API clients; add such a restriction only when that is intended. See [HOME_ASSISTANT.md](HOME_ASSISTANT.md).
- **Debugging a new upstream** — `reverse-proxy-only`: TLS + Host routing only; **no** WAF, CrowdSec, IPBL, or rate limit for that hostname. Intended for short-lived troubleshooting, not production.
- **Internal Zabbix (web UI as an application)** — `trusted-lan` preset: no profile path blocks, basic WAF or bot heuristics while keeping rate limits and CrowdSec. For an **on-host Zabbix agent** listening on TCP 10050 (not published through HAProxy), open the port in nftables via Settings → Monitoring — see [MONITORING.md](MONITORING.md#zabbix-agent-optional-on-host).
- **Nextcloud with GeoIP deny list** — `custom`, enable **GeoIP**, policy `deny`, country list of regions to block; keep other layers as needed.

## API

- `GET /api/v1/security/modes` — preset catalogue for the UI
- `GET|PUT|PATCH /api/v1/applications/{id}/security` — read or update the `security` JSON
- `POST /api/v1/applications/{id}/security/mode` — apply a preset (`{"mode":"…"}`); audited as `app_security_mode_changed` (detail includes `level":"warn"` when switching to `reverse-proxy-only`)
